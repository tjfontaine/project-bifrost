#!/usr/bin/env bifrost
/*
 * strings.d — strstr / index / strjoin / substr.
 *
 * Exercises every string built-in:
 *
 *   - strstr(s, sub)   → pointer to first occurrence (or NULL)
 *   - index(s, sub)    → byte offset (-1 if not found)
 *   - strjoin(a, b)    → concatenation in per-CPU scratch
 *   - substr(s, i, l)  → l-byte slice starting at i
 *   - strlen(s)        → byte count up to NUL, capped at 256
 *   - copyinstr(uaddr) → user-string snapshot
 *
 * The scratch buffers are reused across calls in the same probe,
 * so chain consumers like `printf("%s + %s = %s", a, b, strjoin(a,b))`
 * must not rely on `a` / `b` retaining their pre-call contents.
 * The pattern below stages each result into a `printf` immediately
 * after compute so the per-CPU scratch is always fresh.
 *
 *   sudo bifrost -p $PID -s examples/primers/strings.d
 *
 * Should print one line per openat() with the path's basename
 * (via strrchr) and an idx==0 column showing whether the path
 * begins with "/var".
 */

#pragma D option quiet

syscall::openat:entry
{
    this->path = copyinstr(arg1);
    this->dot  = strrchr(this->path, '.');
    this->is_var = index(this->path, "/var") == 0;
    printf("path=%s ext=%s is_var=%d len=%d\n",
           this->path,
           this->dot != NULL ? this->dot + 1 : "<none>",
           this->is_var,
           strlen(this->path));
}
