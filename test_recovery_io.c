/* Safe syscall mocks: never opens any device. */
#define main recovery_main
#define open mock_open
#define close mock_close
#define fstat mock_fstat
#define ioctl mock_ioctl
#define pread mock_pread
#define pwrite mock_pwrite
#define read mock_read
#define write mock_write
#define fsync mock_fsync
#include "recovery-io.c"
#undef main
#include <assert.h>
#include <stdarg.h>
static int opens, io_calls, closed, mode;
int mock_open(const char *p, int flags, ...) {
    assert(!strcmp(p, "/dev/nvme0n1"));
    assert((flags & (O_EXCL | O_NOFOLLOW | O_CLOEXEC)) == (O_EXCL | O_NOFOLLOW | O_CLOEXEC));
    ++opens;
    if (mode == 1) { errno = EBUSY; return -1; }
    if (mode == 2) { errno = ELOOP; return -1; }
    return 42;
}
int mock_close(int fd) { assert(fd == 42); ++closed; return 0; }
int mock_fstat(int fd, struct stat *s) {
    assert(fd == 42);
    memset(s, 0, sizeof *s);
    s->st_mode = mode == 3 ? S_IFREG : S_IFBLK;
    s->st_rdev = makedev(259, mode == 4 ? 1 : 0);
    return 0;
}
int mock_ioctl(int fd, unsigned long op, ...) {
    assert(fd == 42);
    va_list ap; va_start(ap, op); void *out = va_arg(ap, void *); va_end(ap);
    if (op == BLKGETSIZE64) *(uint64_t *)out = mode == 5 ? 8192 : 4096;
    else if (op == BLKSSZGET) *(int *)out = mode == 6 ? 4096 : 512;
    else if (op == BLKROGET) *(int *)out = mode == 7;
    else assert(0);
    return 0;
}
ssize_t mock_pread(int fd, void *p, size_t n, off_t offset) {
    assert(fd == 42 && offset == 0); ++io_calls; memset(p, 0, n); return (ssize_t)n;
}
ssize_t mock_pwrite(int fd, const void *p, size_t n, off_t offset) {
    (void)p; assert(fd == 42 && offset == 0); ++io_calls; return (ssize_t)n;
}
ssize_t mock_read(int fd, void *p, size_t n) { assert(fd == 0); memset(p, 0, n); return (ssize_t)n; }
ssize_t mock_write(int fd, const void *p, size_t n) { (void)p; assert(fd == 1); return (ssize_t)n; }
int mock_fsync(int fd) { assert(fd == 42); return 0; }
int main(void) {
    char *args[] = {"helper", "write", "/dev/nvme0n1", "259", "0", "4096", "0", "512", NULL};
    for (mode = 0; mode <= 7; ++mode) {
        opens = io_calls = closed = 0;
        int rc = recovery_main(8, args);
        assert(opens == 1);
        assert((rc == 0) == (mode == 0));
        assert(io_calls == (mode == 0 ? 1 : 0));
        assert(closed == (mode == 1 || mode == 2 ? 0 : 1));
    }
    args[1] = "read"; mode = 0; opens = io_calls = 0;
    assert(recovery_main(8, args) == 0 && opens == 1 && io_calls == 1);
    args[6] = "4096"; opens = 0;
    assert(recovery_main(8, args) == 2 && opens == 0);
    puts("native exclusive-FD: valid read/write and 8 refusal scenarios passed (syscall mocks only)");
    return 0;
}
