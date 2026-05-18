#!/usr/bin/env bifrost
/*
 * progeny.d — `progenyof(pid)` ancestor predicate.
 *
 * Filters fires to those whose `current` task is `pid` or a
 * descendant of `pid`. Implemented via a kfunc that walks
 * `current->real_parent` up to init under RCU; depth is capped
 * at 64 to keep the verifier happy and guard against corrupt
 * task_struct chains.
 *
 *   PID=$$ sudo bifrost -p $TARGET_PID -s examples/primers/progeny.d
 *
 * Replace $PID with your shell's PID. Only fires that originate
 * from your shell or its descendants will be printed.
 */

#pragma D option quiet

fbt:guest:do_sys_openat2:entry
/progenyof($1)/
{
    printf("open from progeny pid=%d execname=%s\n", pid, execname);
}
