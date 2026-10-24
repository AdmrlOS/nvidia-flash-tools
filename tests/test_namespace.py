"""Actual native namespace code/main dispatch against path-redirection fixture."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

class NamespaceTests(unittest.TestCase):
    def test_namespace_holders_mounts_swaps_identity_and_main_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);exe=root/'fixture'
            subprocess.run(['/usr/bin/gcc','-O0','-Wall','-Wextra','-Werror','-include','sys/sysmacros.h','-include','linux/fs.h',str(Path(__file__).resolve().parent.parent.joinpath('native_namespace_fixture.c')),'-lcrypto','-o',str(exe)],check=True)
            device=root/'sys/devices/nvme/controller';device.mkdir(parents=True)
            (device/'serial').write_text('serial\n');(device/'model').write_text('model\n')
            for n,dev in [('nvme0n1','259:0'),('nvme0n1p1','259:1')]:
                p=root/'sys/class/block'/n;(p/'holders').mkdir(parents=True)
                (p/'dev').write_text(dev+'\n')
            (root/'sys/class/block/nvme0n1/device').symlink_to(device)
            mounts=root/'proc/self/mountinfo';mounts.parent.mkdir(parents=True);mounts.write_text('')
            swaps=root/'proc/swaps';swaps.write_text('Filename Type Size Used Priority\n')
            (root/'dev').mkdir();(root/'dev/nvme0n1').write_bytes(bytes(4096))
            def run(mode='namespace',data=b''):
                return subprocess.run([str(exe),str(root),mode,str(device)],input=data,capture_output=True,timeout=5)
            self.assertEqual(run().returncode,0)
            holder=root/'sys/class/block/nvme0n1p1/holders/dm-0';holder.write_text('')
            self.assertEqual(run().returncode,1);holder.unlink()
            mounts.write_text('1 2 259:1 / /mnt rw - ext4 /dev/nvme0n1p1 rw\n')
            self.assertEqual(run().returncode,1);mounts.write_text('')
            swaps.write_text('/nonexistent-swap partition 1 0 -2\n')
            self.assertEqual(run().returncode,1);swaps.write_text('Filename Type Size Used Priority\n')
            (device/'serial').write_text('changed')
            self.assertEqual(run().returncode,1);(device/'serial').write_text('serial')
            self.assertEqual(run('session',struct.pack('>cQI32s',b'Q',0,0,bytes(32))).returncode,0)
            self.assertEqual(run('session',b'W').returncode,1)
            self.assertEqual((root/'dev/nvme0n1').read_bytes(),bytes(4096))

if __name__=='__main__':unittest.main()
