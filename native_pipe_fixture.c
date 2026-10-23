/* Execute the production session protocol against a real regular tempfile.
 * Only the fstat/ioctl and sysfs boundary are mocked; no device node is opened.
 */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/wait.h>
#include <openssl/sha.h>
static int safe_calls, unsafe;
static int fake_safe(const char*, unsigned, unsigned, const char*, const char*, const char*);
static int fake_stat(int,struct stat*);
static int fake_ioctl(int,unsigned long,...);
#define main recovery_unused_main
#define RECOVERY_NAMESPACE_CHECK fake_safe
#define fstat fake_stat
#define ioctl fake_ioctl
#include "recovery-io.c"
#undef RECOVERY_NAMESPACE_CHECK
#undef fstat
#undef ioctl
#undef main
/* session calls compiled above use production_namespace_safe; syscall mocks for
 * actual sysfs are cumbersome, so compile-time test boundary below is explicit. */
static int fake_stat(int fd, struct stat *s) {
    int rc=fstat(fd,s); s->st_mode=S_IFBLK|0600; s->st_rdev=makedev(259,0);return rc;
}
static int fake_ioctl(int fd,unsigned long op,...) {
    (void)fd;va_list a;va_start(a,op);void *p=va_arg(a,void*);va_end(a);
    if(op==BLKGETSIZE64)*(uint64_t*)p=4096;
    else if(op==BLKSSZGET)*(int*)p=512;
    else if(op==BLKROGET)*(int*)p=0;
    else return -1;
    return 0;
}
static int fake_safe(const char *n,unsigned a,unsigned b,const char*s,const char*m,const char*d) {
    (void)n;(void)a;(void)b;(void)s;(void)m;(void)d;++safe_calls;return unsafe?-1:0;
}

int main(int argc, char **argv) {
    (void)namespace_safe;
    if(argc!=2)return 2;
    int fd=atoi(argv[1]); struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size!=4096)return 2;
    return session(fd,"nvme0n1",259,0,4096,"serial","model","/sys/mock");
}
