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

static void test_frame(int fd,int corrupt,int stale) {
    int request[2],response[2];assert(!pipe(request)&&!pipe(response));
    pid_t child=fork();assert(child>=0);
    if(!child) {
        close(request[1]);close(response[0]);
        assert(dup2(request[0],0)==0 && dup2(response[1],1)==1);
        unsafe=stale;
        _exit(session(fd,"nvme0n1",259,0,4096,"serial","model","/sys/mock"));
    }
    close(request[0]);close(response[1]);
    unsigned char frame[45]={0},data[512],reply[36],hash[32];
    memset(data,'x',sizeof data);frame[0]='W';frame[11]=2;
    SHA256(data,sizeof data,frame+13);if(corrupt)frame[13]^=1;
    assert(!exact(request[1],frame,sizeof frame,1));
    assert(!exact(request[1],data,sizeof data,1));
    if(!corrupt && !stale) {
        assert(!exact(response[0],reply,sizeof reply,0));assert(reply[3]==32);
        assert(!exact(response[0],hash,32,0));
        assert(!memcmp(hash,frame+13,32));
        memset(frame,0,sizeof frame);frame[0]='R';frame[11]=2;
        assert(!exact(request[1],frame,sizeof frame,1));
        assert(!exact(response[0],reply,sizeof reply,0));
        assert(!exact(response[0],data,sizeof data,0));
        for(unsigned i=0;i<sizeof data;i++)assert(data[i]=='x');
        memset(frame,0,sizeof frame);frame[0]='Q';
        assert(!exact(request[1],frame,sizeof frame,1));
    }
    close(request[1]);close(response[0]);int status;assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status));assert(WEXITSTATUS(status)==(corrupt||stale?1:0));
}
int main(void) {
    (void)namespace_safe;
    char name[4096];const char *tmp=getenv("TMPDIR");assert(tmp);
    snprintf(name,sizeof name,"%s/native-protocol-XXXXXX",tmp);
    int fd=mkstemp(name);assert(fd>=0);assert(!unlink(name));assert(!ftruncate(fd,4096));
    test_frame(fd,0,0);
    unsigned char zero[512]={0},actual[512];assert(pwrite(fd,zero,512,0)==512);
    test_frame(fd,1,0);assert(pread(fd,actual,512,0)==512&&!memcmp(zero,actual,512));
    test_frame(fd,0,1);assert(pread(fd,actual,512,0)==512&&!memcmp(zero,actual,512));
    close(fd);puts("native framed session: retained real file FD write/read, bad hash and stale identity refusal passed");return 0;
}
