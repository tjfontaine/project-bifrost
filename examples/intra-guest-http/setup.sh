#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — intra-guest HTTP load.  Boots localhost:5005/bifrost-bench:latest in smolvm
# and runs short in-guest Perl loopback client/server bursts via
# `smolvm machine exec`, so loopback traffic traverses the guest
# TCP stack and tcp_v4_do_rcv fires while bifrost is attached.
#
# Each burst starts its own loopback server and client inside a
# single short exec call.  That keeps both endpoints in the same
# guest network namespace without depending on a persistent
# container workload.
#
# After this script reports "ready", open another shell and run
# bifrost yourself, dtrace-style:
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -s examples/intra-guest-http/probe.d
#
# When you are done tracing (^C the bifrost CLI), come back here
# and ^C this script too — it tears down the smolvm.
#
# Knobs (env):
#   HTTP_REQS     requests per exec burst (default: 200)
#   IMAGE         base image            (default: localhost:5005/bifrost-bench:latest)

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

echo "[setup] launching $IMAGE — entrypoint idles; setup drives loopback TCP bursts"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID"

echo "[setup] starting loopback TCP exec burst loop"
(
    while :; do
        "$SMOLVM" machine exec -- perl -MIO::Socket::INET -e '
            my $n = shift || 200;
            my $srv = IO::Socket::INET->new(LocalAddr=>"127.0.0.1", LocalPort=>18080, Listen=>16, Reuse=>1, Proto=>"tcp") or die $!;
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
                my $c = IO::Socket::INET->new(PeerAddr=>"127.0.0.1", PeerPort=>18080, Proto=>"tcp") or next;
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
[setup] ready. loopback TCP bursts running in-guest, smolvm pid=$PID
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/intra-guest-http/probe.d
[setup]
[setup] this shell will idle until ^C, when it tears down the VM.
[setup] ════════════════════════════════════════════════════════════

MSG

while :; do
    sleep 60
done
