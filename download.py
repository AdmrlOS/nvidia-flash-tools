"""Stdlib HTTPS downloads; exact authenticated manifest bytes authorize inputs."""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import urllib.parse
import urllib.request
from security import trusted_directory


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('HTTPS downgrade refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(record, directory, *, opener=None):
    name, url, size, pin = (record[k] for k in ('name','url','size','sha256'))
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
            not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in ('.','..') or
            not isinstance(size,int) or size <= 0 or not re.fullmatch('[0-9a-f]{64}',pin)):
        raise ValueError('invalid pinned HTTPS artifact record')
    directory=Path(directory).absolute()
    parent=trusted_directory(directory,owner=os.geteuid())
    part=name+'.part'
    def regular(fd):
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('unsafe download file')
        return info
    def verify(fd):
        info=regular(fd);os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256()
        while block:=os.read(fd,1024*1024):h.update(block)
        if info.st_size != size or h.hexdigest()!=pin:raise ValueError('download size/SHA256 mismatch')
    fd=None
    authorized=False
    try:
        try:existing=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:existing=None
        if existing is not None:
            try:verify(existing)
            finally:os.close(existing)
            return directory/name
        fd=os.open(part,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);regular(fd)
        authorized=True
        offset=os.fstat(fd).st_size
        if offset > size:os.ftruncate(fd,0);offset=0
        if offset < size:
            request=urllib.request.Request(url,headers={'Range':'bytes=%d-'%offset} if offset else {})
            open_url=opener or urllib.request.build_opener(HTTPSRedirect()).open
            with open_url(request,timeout=60) as response:
                if urllib.parse.urlsplit(response.geturl()).scheme!='https':raise ValueError('HTTPS required')
                if response.status==206:
                    expected='bytes %d-%d/%d'%(offset,size-1,size)
                    if response.headers.get('Content-Range')!=expected:raise ValueError('invalid resume Content-Range')
                elif response.status==200:
                    os.ftruncate(fd,0);offset=0
                else:raise ValueError('unsupported HTTPS response')
                os.lseek(fd,offset,os.SEEK_SET)
                while block:=response.read(min(1024*1024,size-offset+1)):
                    offset+=len(block)
                    if offset>size:raise ValueError('download oversized')
                    view=memoryview(block)
                    while view:
                        n=os.write(fd,view)
                        if n<=0:raise ValueError('download short write')
                        view=view[n:]
                os.fsync(fd)
        verify(fd)
        # Publish without overwriting another file (even a concurrent symlink).
        os.link(part,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        os.unlink(part,dir_fd=parent);os.fsync(parent)
        return directory/name
    except ValueError:
        if authorized:os.ftruncate(fd,0)
        raise
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def guided(args, release, *, consent=input, fetcher=fetch):
    if not args.download_dir:
        raise ValueError('--download-dir required for verified download')
    print('NVIDIA proprietary software: review the license notices supplied at the NVIDIA release page:')
    print(release['nvidia']['source'])
    print('Downloading does not authorize redistribution or accept terms on anyone else\'s behalf.')
    if not args.accept_nvidia_license and consent('After reviewing NVIDIA terms, type I ACCEPT NVIDIA LICENSE: ').strip()!='I ACCEPT NVIDIA LICENSE':
        raise ValueError('explicit NVIDIA license acknowledgement required')
    args.download_dir.mkdir(mode=0o700,parents=False,exist_ok=True)
    for key, attribute in (('archive','nvidia_archive'),('sample_rootfs','sample_rootfs')):
        record=release['nvidia'][key]
        print('Verifying/downloading %s (%d bytes, SHA256 %s)'%(record['name'],record['size'],record['sha256']))
        setattr(args,attribute,fetcher(record,args.download_dir))
    return args
