#include <syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

// argv[0] = program name
// argv[1] = file offset (decimal string)
// argv[2] = file path
// argv[3] = optional "r" — read mode: write 16 bytes of file content to fd 0 (OUT_FD)
//           "h" — handoff mode: send the opened file descriptor to the parent
//                 over fd 1 (SCM_RIGHTS), so the caller can splice the page
//                 itself; the clone has no CLONE_FILES, so this is the only
//                 way the descriptor crosses the process boundary
//           if absent — splice mode: splice 16 bytes of file page into fd 1 (PIPE_FD)

#define OUT_FD  0
#define PIPE_FD 1

__attribute__((naked)) static long mysyscall1(unsigned long arg0, unsigned long nr) {
    asm volatile("mov x8, x1\nsvc 0\nret\n":::"x8");
}

__attribute__((naked)) static long mysyscall3(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long nr) {
    asm volatile("mov x8, x3\nsvc 0\nret\n":::"x8");
}

__attribute__((naked)) static long mysyscall6(
    unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5, unsigned long nr) {
    asm volatile("mov x8, x6\nsvc 0\nret\n":::"x8");
}

static unsigned long parse_int(char *s) {
    unsigned long val = 0;
    while (*s) { val = val * 10 + (unsigned long)(*s - '0'); s++; }
    return val;
}

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

void start_c(void *argblock) {
    int argc = (int)*(long *)argblock;
    char **argv = (char **)argblock + 1;

    if (argc < 3 || argc > 4)
        mysyscall1(1, __NR_exit_group);

    off64_t off = (off64_t)parse_int(argv[1]);
    char *target = argv[2];
    char *mode = (argc >= 4) ? argv[3] : (char *)0;

    int file_fd = (int)mysyscall3(
        (unsigned long)AT_FDCWD,
        (unsigned long)target,
        (unsigned long)O_RDONLY,
        __NR_openat);
    if (file_fd < 0)
        mysyscall1(1, __NR_exit_group);

    if (mode && streq(mode, "r")) {
        /* Read mode: lseek to offset, read 16 bytes, write to OUT_FD */
        /* Exit codes: 0=ok, 1=read<16, 2=write<16, 3=OUT_FD not a pipe (fd sanitized) */
        mysyscall3((unsigned long)file_fd, (unsigned long)off, SEEK_SET, __NR_lseek);
        unsigned char buf[16];
        long n = mysyscall3((unsigned long)file_fd, (unsigned long)buf, 16, __NR_read);
        if (n != 16)
            mysyscall1(1, __NR_exit_group);
        if (mysyscall3(OUT_FD, 0, SEEK_CUR, __NR_lseek) != (long)-29L) /* ESPIPE: fd is a pipe */
            mysyscall1(3, __NR_exit_group);
        long w = mysyscall3(OUT_FD, (unsigned long)buf, 16, __NR_write);
        mysyscall1((unsigned long)(w == 16 ? 0 : 2), __NR_exit_group);
    }

    if (mode && streq(mode, "h")) {
        /* Exit code 0 = descriptor sent, 4 = sendmsg failed */
        struct msghdr msg;
        union {
            struct cmsghdr align;
            char buf[CMSG_SPACE(sizeof(int))];
        } cbuf;
        unsigned char *z;
        unsigned long i;
        struct cmsghdr *cm;

        z = (unsigned char *)&msg;
        for (i = 0; i < sizeof(msg); i++) z[i] = 0;
        z = (unsigned char *)&cbuf;
        for (i = 0; i < sizeof(cbuf); i++) z[i] = 0;

        msg.msg_control = cbuf.buf;
        msg.msg_controllen = sizeof(cbuf.buf);

        cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type  = SCM_RIGHTS;
        cm->cmsg_len   = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cm) = file_fd;

        long r = mysyscall3(PIPE_FD, (unsigned long)&msg, 0, __NR_sendmsg);
        mysyscall1((unsigned long)(r >= 0 ? 0 : 4), __NR_exit_group);
    }

    /* Splice mode: splice 16-byte page into PIPE_FD */
    long ret = mysyscall6(
        (unsigned long)file_fd,
        (unsigned long)&off,
        PIPE_FD,
        (unsigned long)NULL,
        16,
        SPLICE_F_MOVE,
        __NR_splice);
    mysyscall1((unsigned long)(ret == 16 ? 0 : 1), __NR_exit_group);
}

__attribute__((naked)) void _start() {
    asm(".extern start_c\nmov x0, sp\nb start_c\n");
}
