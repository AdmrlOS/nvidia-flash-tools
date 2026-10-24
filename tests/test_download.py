"""Verified downloader: transport mocked, all local bytes real."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest

class Response(io.BytesIO):
    def __init__(self,data,status=200,headers=None):
        super().__init__(data);self.status=status;self.headers=headers or {}
    def geturl(self):return 'https://developer.nvidia.com/pinned'

class DownloadTests(unittest.TestCase):
    def test_license_refusal_has_no_network_or_directory_side_effect(self):
        import argparse
        from nvidia_flash_tools.download import guided
        args=argparse.Namespace(download_dir=self.root/'new',accept_nvidia_license=False)
        with self.assertRaisesRegex(ValueError,'acknowledgement'):
            guided(args,{'nvidia':{'source':'https://developer.nvidia.com/release'}},consent=lambda prompt:'no',fetcher=lambda *a:self.fail('download before consent'))
        self.assertFalse(args.download_dir.exists())


    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.data=b'actual downloaded bytes'*300
        self.record={'name':'bsp.tbz2','url':'https://developer.nvidia.com/pinned', 'size':len(self.data),'sha256':hashlib.sha256(self.data).hexdigest()}

    def test_atomic_verified_download_and_existing_recheck(self):
        from nvidia_flash_tools.download import fetch
        p=fetch(self.record,self.root,opener=lambda req,timeout:Response(self.data))
        self.assertEqual(p.read_bytes(),self.data)
        self.assertEqual(fetch(self.record,self.root,opener=lambda *a,**k:self.fail('network')),p)
        p.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'mismatch'):fetch(self.record,self.root)

    def test_resume_range_and_server_ignoring_range_restart(self):
        from nvidia_flash_tools.download import fetch
        part=self.root/'bsp.tbz2.part';part.write_bytes(self.data[:101]);part.chmod(0o600)
        def opened(req,timeout):
            self.assertEqual(req.get_header('Range'),'bytes=101-')
            return Response(self.data[101:],206,{'Content-Range':'bytes 101-%d/%d'%(len(self.data)-1,len(self.data))})
        self.assertEqual(fetch(self.record,self.root,opener=opened).read_bytes(),self.data)
        (self.root/'bsp.tbz2').unlink();part.write_bytes(self.data[:101]);part.chmod(0o600)
        self.assertEqual(fetch(self.record,self.root,opener=lambda *a,**k:Response(self.data)).read_bytes(),self.data)

    def test_completed_partial_publishes_without_416_request(self):
        from nvidia_flash_tools.download import fetch
        (self.root/'bsp.tbz2.part').write_bytes(self.data)
        (self.root/'bsp.tbz2.part').chmod(0o600)
        self.assertEqual(fetch(self.record,self.root,opener=lambda *a,**k:self.fail('completed download requested')).read_bytes(),self.data)

    def test_corrupt_and_oversized_never_published(self):
        from nvidia_flash_tools.download import fetch
        for data in (b'bad',b'x'*(len(self.data)+1)):
            with self.assertRaises(ValueError):fetch(self.record,self.root,opener=lambda *a,**k:Response(data))
            self.assertFalse((self.root/'bsp.tbz2').exists())

    def test_symlink_and_http_rejected(self):
        from nvidia_flash_tools.download import fetch
        victim=self.root/'victim';victim.write_bytes(b'safe')
        (self.root/'bsp.tbz2.part').symlink_to(victim)
        with self.assertRaises((ValueError,OSError)):fetch(self.record,self.root,opener=lambda *a,**k:Response(self.data))
        self.assertEqual(victim.read_bytes(),b'safe')
        self.record['url']='http://developer.nvidia.com/file'
        with self.assertRaises(ValueError):fetch(self.record,self.root)


    def test_rejected_partial_hardlink_and_writable_victims_unchanged(self):
        from nvidia_flash_tools.download import fetch
        part=self.root/'bsp.tbz2.part'
        victim=self.root/'unrelated';original=b'precious unrelated contents'
        victim.write_bytes(original);victim.chmod(0o600)
        os.link(victim,part)
        with self.assertRaisesRegex(ValueError,'unsafe'):fetch(self.record,self.root)
        self.assertEqual(victim.read_bytes(),original);self.assertEqual(part.read_bytes(),original)
        self.assertEqual(victim.stat().st_nlink,2);part.unlink()
        for mode in (0o620,0o602,0o666):
            part.write_bytes(original);part.chmod(mode)
            with self.assertRaisesRegex(ValueError,'unsafe'):fetch(self.record,self.root)
            self.assertEqual(part.read_bytes(),original);self.assertEqual(part.stat().st_mode & 0o777,mode)
            part.unlink()

    def test_FIFO_and_locked_partial_preserved(self):
        import fcntl,stat
        from nvidia_flash_tools.download import fetch
        part=self.root/'bsp.tbz2.part';os.mkfifo(part,0o600)
        with self.assertRaises((ValueError,OSError)):fetch(self.record,self.root)
        self.assertTrue(stat.S_ISFIFO(part.stat().st_mode));part.unlink()
        part.write_bytes(b'another transfer');part.chmod(0o600)
        with part.open('r+b') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):fetch(self.record,self.root)
            self.assertEqual(part.read_bytes(),b'another transfer')

    def test_wrong_owner_preserved_where_permitted(self):
        from nvidia_flash_tools.download import fetch
        from unittest.mock import patch
        part=self.root/'bsp.tbz2.part';part.write_bytes(b'foreign-owned partial');part.chmod(0o600)
        try:os.chown(part,65534,-1)
        except PermissionError:
            # Exercise actual fstat and bytes with only the owner comparison
            # altered; unprivileged runners cannot create foreign-owned files.
            from nvidia_flash_tools import download
            with patch('nvidia_flash_tools.download.os.geteuid',return_value=os.geteuid()+1),patch('nvidia_flash_tools.download.trusted_directory',side_effect=lambda *a,**k:os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)):
                with self.assertRaisesRegex(ValueError,'unsafe'):fetch(self.record,self.root)
        else:
            with self.assertRaisesRegex(ValueError,'unsafe'):fetch(self.record,self.root)
        self.assertEqual(part.read_bytes(),b'foreign-owned partial')

if __name__=='__main__':unittest.main()
