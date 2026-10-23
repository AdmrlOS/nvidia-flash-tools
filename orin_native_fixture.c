/* Path-redirected filesystem fixture: production namespace_safe AND main session
 * dispatch, real regular-file descriptor; only block geometry/stat are mocked.
 * No /dev node is opened. Production source is included unchanged. */
#define _GNU_SOURCE
#include <assert.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char root[4096];
static const char *mapped(const char *p,char *out) {
 if(!strncmp(p,"/sys/",5)||!strncmp(p,"/proc/",6)||!strcmp(p,"/dev/nvme0n1")) {
  assert(snprintf(out,8192,"%s%s",root,p)<8192);return out;
 }
 return p;
}
static int fixture_open(const char*p,int flags,...){char b[8192];return open(mapped(p,b),flags,0600);}
static FILE *fixture_fopen(const char*p,const char*m){char b[8192];return fopen(mapped(p,b),m);}
static DIR *fixture_opendir(const char*p){char b[8192];return opendir(mapped(p,b));}
static char *fixture_realpath(const char*p,char*out){char b[8192];return realpath(mapped(p,b),out);}
static int fixture_fstat(int fd,struct stat*s){int r=fstat(fd,s);s->st_mode=S_IFBLK|0600;s->st_rdev=makedev(259,0);return r;}
static int fixture_ioctl(int fd,unsigned long op,...){
 (void)fd;va_list a;va_start(a,op);void*p=va_arg(a,void*);va_end(a);
 if(op==BLKGETSIZE64){struct stat s;if(fstat(fd,&s))return -1;*(unsigned long long*)p=(unsigned long long)s.st_size;}
 else if(op==BLKSSZGET)*(int*)p=512;
 else if(op==BLKROGET)*(int*)p=0;
 else return -1;
 return 0;
}
#define main production_main
#define open fixture_open
#define fopen fixture_fopen
#define opendir fixture_opendir
#define realpath fixture_realpath
#define fstat fixture_fstat
#define ioctl fixture_ioctl
#include "recovery-io.c"
#undef main
#undef open
#undef fopen
#undef opendir
#undef realpath
#undef fstat
#undef ioctl
int main(int argc,char**argv){
 assert(argc==5);assert(strlen(argv[1])<sizeof root);strcpy(root,argv[1]);
 char *args[]={"helper","session","/dev/nvme0n1","259","0",argv[4],"0","512","serial","model",argv[3]};
 return production_main(11,args);
}
