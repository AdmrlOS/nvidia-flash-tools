/* Native recovery I/O boundary. Host framed integration implemented; hardware unqualified.
 * No pathname reopen, inherited-FD trick or shell/dd fallback is permitted.
 * O_EXCL block opens reject mounted/claimed devices; validate actual rdev and
 * geometry on that same descriptor before the first pread/pwrite.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/sha.h>

static int number(const char *text, uint64_t *out) {
    char *end;
    if (!*text || strspn(text, "0123456789") != strlen(text)) return -1;
    errno = 0;
    *out = strtoull(text, &end, 10);
    return errno || *end ? -1 : 0;
}

static int transfer(int fd, uint64_t offset, size_t length, int writing) {
    unsigned char buffer[65536];
    while (length) {
        size_t count = length < sizeof buffer ? length : sizeof buffer;
        size_t done = 0;
        while (done < count) {
            /* Explicit object bounds keep fortified optimized builds able to
             * prove the subtraction cannot wrap across a partial syscall. */
            if (count > sizeof buffer || done >= sizeof buffer) return -1;
            size_t available = count - done;
            if (available > sizeof buffer || available > sizeof buffer - done) return -1;
            ssize_t n = writing ? read(STDIN_FILENO, buffer + done, available)
                                : pread(fd, buffer + done, available, (off_t)(offset + done));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || (size_t)n > count - done) return -1;
            done += (size_t)n;
        }
        done = 0;
        while (done < count) {
            ssize_t n = writing ? pwrite(fd, buffer + done, count - done, (off_t)(offset + done))
                                : write(STDOUT_FILENO, buffer + done, count - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || (size_t)n > count - done) return -1;
            done += (size_t)n;
        }
        length -= count;
        offset += count;
    }
    return writing ? fsync(fd) : 0;
}

/* Framed session: 45 byte request = op,u64be offset,u32be length,sha256.
 * Response u32be length,sha256,data. One descriptor for the entire session.
 * EOF, invalid hash, stale identity, holders or mounts ends the session.
 */
static int exact(int fd, void *buf, size_t n, int wr) {
    unsigned char *p = buf;
    while (n) {
        ssize_t k = wr ? write(fd,p,n) : read(fd,p,n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0 || (size_t)k > n) return -1;
        n -= (size_t)k; p += k;
    }
    return 0;
}
static int textfile(const char *path, char *out, size_t n) {
    int f = open(path, O_RDONLY|O_CLOEXEC);
    if (f < 0) return -1;
    ssize_t k = read(f,out,n-1); close(f);
    if (k <= 0 || (size_t)k == n-1) return -1;
    out[k] = 0;
    while (k && (out[k-1]=='\n' || out[k-1]==' ')) out[--k]=0;
    return 0;
}
static int emptydir(const char *path) {
    DIR *d=opendir(path); struct dirent *e;
    if (!d) return -1;
    while ((e=readdir(d))) if (strcmp(e->d_name,".") && strcmp(e->d_name,"..")) {
        closedir(d); return -1;
    }
    closedir(d); return 0;
}
#ifndef RECOVERY_NAMESPACE_CHECK
#define RECOVERY_NAMESPACE_CHECK namespace_safe
#endif
static int namespace_safe(const char *name, unsigned maj, unsigned min,
                          const char *serial, const char *model, const char *expected_device) {
    char path[512], text[512], expected[64], resolved[4096];
    snprintf(path,sizeof path,"/sys/class/block/%s/device",name);
    if (!realpath(path,resolved) || !strstr(resolved,"/nvme/") || strcmp(resolved,expected_device)) return -1;
    snprintf(path,sizeof path,"/sys/class/block/%s/device/serial",name);
    if (textfile(path,text,sizeof text) || strcmp(text,serial)) return -1;
    snprintf(path,sizeof path,"/sys/class/block/%s/device/model",name);
    if (textfile(path,text,sizeof text) || strcmp(text,model)) return -1;
    snprintf(path,sizeof path,"/sys/class/block/%s/dev",name);
    snprintf(expected,sizeof expected,"%u:%u",maj,min);
    if (textfile(path,text,sizeof text) || strcmp(text,expected)) return -1;
    /* All namespace descendants (partitions included) must be unused. */
    DIR *d=opendir("/sys/class/block"); struct dirent *e;
    if (!d) return -1;
    FILE *mounts=fopen("/proc/self/mountinfo","r"), *swaps=fopen("/proc/swaps","r");
    if (!mounts || !swaps) { if(mounts)fclose(mounts); if(swaps)fclose(swaps); closedir(d); return -1; }
    int ok=0;
    while ((e=readdir(d))) {
        size_t len=strlen(name);
        if (strncmp(e->d_name,name,len) || (e->d_name[len] && e->d_name[len]!='p')) continue;
        snprintf(path,sizeof path,"/sys/class/block/%s/holders",e->d_name);
        if (emptydir(path)) { ok=-1; break; }
        snprintf(path,sizeof path,"/sys/class/block/%s/dev",e->d_name);
        if (textfile(path,text,sizeof text)) { ok=-1; break; }
        rewind(mounts);
        char *line=NULL; size_t cap=0;
        while (getline(&line,&cap,mounts)>0) {
            unsigned a,b; char dev[64];
            if (sscanf(line,"%u %u %63s",&a,&b,dev)!=3 || !strcmp(dev,text)) { ok=-1; break; }
        }
        free(line); if(ok)break;
        rewind(swaps); line=NULL; cap=0;
        while (getline(&line,&cap,swaps)>0) {
            char dev[4096]; struct stat st;
            if (sscanf(line,"%4095s",dev)!=1) {ok=-1;break;}
            if (dev[0]=='/' && stat(dev,&st)) {ok=-1;break;}
            if (dev[0]=='/' && S_ISBLK(st.st_mode)) {
                snprintf(expected,sizeof expected,"%u:%u",major(st.st_rdev),minor(st.st_rdev));
                if(!strcmp(expected,text)){ok=-1;break;}
            }
        }
        free(line); if(ok)break;
    }
    fclose(mounts); fclose(swaps); closedir(d); return ok;
}
static int session(int fd, const char *name, unsigned maj, unsigned min,
                   uint64_t capacity, const char *serial, const char *model, const char *expected_device) {
    unsigned char header[45], hash[32], reply[36];
    unsigned char *data=malloc(4194304);
    if(!data)return 1;
    int result=1;
    for (;;) {
        if(exact(0,header,sizeof header,0))break;
        uint64_t offset=0; uint32_t length=0;
        for(int i=1;i<9;i++)offset=(offset<<8)|header[i];
        for(int i=9;i<13;i++)length=(length<<8)|header[i];
        struct stat current; uint64_t size=0; int ro=1, sector=0;
        if(fstat(fd,&current) || !S_ISBLK(current.st_mode) ||
           major(current.st_rdev)!=maj || minor(current.st_rdev)!=min ||
           ioctl(fd,BLKGETSIZE64,&size) || size!=capacity ||
           ioctl(fd,BLKSSZGET,&sector) || sector!=512 ||
           ioctl(fd,BLKROGET,&ro) || ro ||
           RECOVERY_NAMESPACE_CHECK(name,maj,min,serial,model,expected_device))break;
        if(header[0]=='Q' && !length && !offset){result=0;break;}
        if(!length || length>4194304 || offset>capacity || length>capacity-offset ||
           offset%512 || length%512 || (header[0]!='R' && header[0]!='W'))break;
        if(header[0]=='W') {
            if(exact(0,data,length,0))break;
            SHA256(data,length,hash);
            if(memcmp(hash,header+13,32))break;
            size_t done=0;
            while(done<length) {
                ssize_t k=pwrite(fd,data+done,length-done,(off_t)(offset+done));
                if(k<0 && errno==EINTR)continue;
                if(k<=0 || (size_t)k>length-done)goto finished;
                done+=(size_t)k;
            }
            if(fsync(fd))break;
        }
        size_t done=0;
        while(done<length) {
            if(length>4194304 || done>=4194304)goto finished;
            size_t available=length-done;
            if(available>4194304 || available>4194304-done)goto finished;
            ssize_t k=pread(fd,data+done,available,(off_t)(offset+done));
            if(k<0 && errno==EINTR)continue;
            if(k<=0 || (size_t)k>length-done)goto finished;
            done+=(size_t)k;
        }
        SHA256(data,length,hash);
        uint32_t output=header[0]=='R'?length:32;
        for(int i=0;i<4;i++)reply[i]=(unsigned char)(output>>(24-8*i));
        if(header[0]=='W'){memcpy(data,hash,32);SHA256(data,32,reply+4);}
        else memcpy(reply+4,hash,32);
        if(exact(1,reply,36,1)||exact(1,data,output,1))break;
    }
finished:
    free(data); return result;
}

int main(int argc, char **argv) {
    uint64_t values[5], bytes = 0;
    struct stat info;
    int sector = 0, readonly = 1, fd, result = 1;
    int persistent = argc == 11 && !strcmp(argv[1], "session");
    if (!persistent && (argc != 8 || (strcmp(argv[1], "read") && strcmp(argv[1], "write")))) return 2;
    /* argv: OP DISK expected-major expected-minor capacity offset length */
    if (strncmp(argv[2], "/dev/nvme", 9)) return 2;
    const char *p = argv[2] + 9;
    if (*p < '0' || *p > '9') return 2;
    while (*p >= '0' && *p <= '9') ++p;
    if (*p++ != 'n' || *p < '0' || *p > '9') return 2;
    while (*p >= '0' && *p <= '9') ++p;
    if (*p) return 2;
    for (int i = 0; i < 5; ++i) if (number(argv[i + 3], &values[i])) return 2;
    if (values[0] > UINT32_MAX || values[1] > UINT32_MAX ||
        !values[2] || values[2] > INT64_MAX || values[2] % 512 ||
        !values[4] || values[4] > 4194304 || values[3] % 512 || values[4] % 512 ||
        values[3] > values[2] || values[4] > values[2] - values[3]) return 2;
    int writing = persistent || !strcmp(argv[1], "write");
    fd = open(argv[2], (writing ? O_RDWR : O_RDONLY) | O_EXCL | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 1;
    if (fstat(fd, &info) || !S_ISBLK(info.st_mode) ||
        major(info.st_rdev) != values[0] || minor(info.st_rdev) != values[1] ||
        ioctl(fd, BLKGETSIZE64, &bytes) || bytes != values[2] ||
        ioctl(fd, BLKSSZGET, &sector) || sector != 512 ||
        ioctl(fd, BLKROGET, &readonly) || readonly) goto out;
    if (persistent)
        result = session(fd, argv[2]+5, (unsigned)values[0], (unsigned)values[1], values[2], argv[8], argv[9], argv[10]);
    else result = transfer(fd, values[3], (size_t)values[4], writing) ? 1 : 0;
out:
    if (close(fd)) result = 1;
    return result;
}
