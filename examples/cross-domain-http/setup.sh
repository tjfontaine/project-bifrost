#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot a smolvm guest and drive loopback HTTP bursts
# inside short `smolvm machine exec` calls.
# Does NOT run the trace.
#
# Host traffic over TSI does not traverse tcp_v4_do_rcv, and the
# long-running image entrypoint is not a reliable validation source
# for this harness.  Each exec burst starts a tiny Perl HTTP server
# and client in the same guest namespace, producing deterministic
# tcp_v4_do_rcv activity while the macOS bifrost CLI observes it
# through libkrun and SHMEM.
#
# Knobs (env):
#   HTTP_REQS     requests per exec burst (default: 200)
#   IMAGE         OCI image (default: localhost:5005/bifrost-bench:latest)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"
HTTP_REQS="${HTTP_REQS:-200}"
FIRE_GAP="${FIRE_GAP:-0.05}"

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

cleanup() {
    echo
    echo "[setup] tearing down"
    sudo -n "$CLEANUP" 2>&1 | tail -2 || true
    "$SMOLVM" machine stop 2>&1 | tail -2 || true
    pkill -P $$ 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

echo "[setup] cleanup leftover bifrost / smolvm processes"
sudo -n "$CLEANUP" 2>&1 | tail -2 || true
"$SMOLVM" machine stop 2>&1 | tail -2 || true
sleep 1

echo "[setup] launching $IMAGE on smolvm — entrypoint idles; setup drives loopback TCP bursts"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
i=0
while [ -z "$PID" ]; do
    sleep 1
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "[setup] timed out waiting for smolvm boot pid" >&2; exit 1; }
    PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
done

echo "[setup] smolvm pid=$PID"

echo "[setup] starting loopback TCP exec burst loop"
(
    while :; do
        "$SMOLVM" machine exec -- perl -MIO::Socket::INET -e '
            my $n = shift || 200;
            my $srv = IO::Socket::INET->new(LocalAddr=>"127.0.0.1", LocalPort=>18081, Listen=>16, Reuse=>1, Proto=>"tcp") or die $!;
            my $pid = fork();
            if (!defined $pid) { die "fork failed"; }
            if ($pid == 0) {
                for (1..$n) {
                    my $c = $srv->accept();
                    next unless $c;
                    sysread($c, my $buf, 1024);
                    print $c "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    close($c);
                }
                exit 0;
            }
            for (1..$n) {
                my $c = IO::Socket::INET->new(PeerAddr=>"127.0.0.1", PeerPort=>18081, Proto=>"tcp") or next;
                print $c "GET / HTTP/1.0\r\n\r\n";
                sysread($c, my $buf, 1024);
                close($c);
            }
            waitpid($pid, 0);
        ' "$HTTP_REQS" >/dev/null 2>&1 || true
        sleep "$FIRE_GAP"
    done
) &
WORKLOAD_PID=$!

echo "[setup] letting loopback TCP bursts settle (5 s)"
sleep 5

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. loopback TCP bursts are running in-guest, smolvm pid=$PID
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/cross-domain-http/probe.d
[setup]
[setup] this shell will idle until ^C, when it tears down the VM.
[setup] ════════════════════════════════════════════════════════════

MSG

while :; do
    sleep 60
done
