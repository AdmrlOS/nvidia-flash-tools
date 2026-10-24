"""Exploit regressions; files and mocked process/syscall boundaries only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zlib

from tests import test_installer
from nvidia_flash_tools.flow import install
from nvidia_flash_tools.image import inspect, sha256
from nvidia_flash_tools.security import trusted_directory
from nvidia_flash_tools.transport import execute, SSH, ADB
from nvidia_flash_tools.vendor import Vendor, inspect_thor_payload, package_hashes, thor_flash_graph
from nvidia_flash_tools.writer import FileDisk, write_image


class SecurityTests(unittest.TestCase):
    setUp = test_installer.InstallerTests.setUp
    tearDown = test_installer.InstallerTests.tearDown

    def write(self, disk=None):
        disk = disk or FileDisk(self.dest)
        return write_image(self.image, disk, sha256(self.image), disk.identity(), {}, self.root / 'journal')

    def mutate_gpt(self, first=None, last=None, part=None):
        data = bytearray(self.image.read_bytes())
        sectors = len(data) // 512
        table = bytearray(data[1024:17408])
        if part:
            part(table)
        crc = zlib.crc32(table)
        for position in (1024, (sectors - 33) * 512):
            data[position:position + 16384] = table
        for position in (512, (sectors - 1) * 512):
            if first is not None: struct.pack_into('<Q', data, position + 40, first)
            if last is not None: struct.pack_into('<Q', data, position + 48, last)
            struct.pack_into('<I', data, position + 88, crc)
            struct.pack_into('<I', data, position + 16, 0)
            struct.pack_into('<I', data, position + 16, zlib.crc32(data[position:position + 92]))
        self.image.write_bytes(data)

    def test_predictable_new_symlink_does_not_clobber(self):
        victim = self.root / 'victim'; victim.write_text('KEEP')
        (self.root / 'journal.new').symlink_to(victim)
        self.write()
        self.assertEqual(victim.read_text(), 'KEEP')

    def test_journal_final_symlink_refused_before_disk_lock(self):
        victim = self.root / 'victim'; victim.write_text('KEEP')
        (self.root / 'journal').symlink_to(victim)
        disk = FileDisk(self.dest)
        with patch.object(disk, 'lock') as lock:
            with self.assertRaises(OSError): self.write(disk)
            lock.assert_not_called()
        disk.unlock(); self.assertEqual(victim.read_text(), 'KEEP')

    def test_journal_fifo_refused_without_blocking(self):
        os.mkfifo(self.root / 'journal')
        disk = FileDisk(self.dest)
        with self.assertRaisesRegex(ValueError, 'untrusted journal'): self.write(disk)
        disk.unlock()

    def test_journal_hardlink_refused(self):
        victim = self.root / 'victim'; victim.write_text('{}'); victim.chmod(0o600)
        os.link(victim, self.root / 'journal')
        disk = FileDisk(self.dest)
        with self.assertRaisesRegex(ValueError, 'untrusted journal'): self.write(disk)
        disk.unlock(); self.assertEqual(victim.read_text(), '{}')

    def test_writable_journal_parent_refused(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'untrusted'): trusted_directory(self.root, os.geteuid())
        self.root.chmod(0o700)

    def test_symlink_journal_parent_refused(self):
        link = self.root / 'link'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): trusted_directory(link, os.geteuid())

    def test_foreign_owned_parent_refused(self):
        with patch('nvidia_flash_tools.security.os.fstat', return_value=argparse.Namespace(st_uid=12345, st_mode=0o700)):
            with self.assertRaisesRegex(ValueError, 'untrusted'): trusted_directory(self.root)

    def test_crc_correct_primary_table_metadata_overlap_refused(self):
        self.mutate_gpt(first=2, part=lambda t: struct.pack_into('<Q', t, 32, 2))
        with self.assertRaisesRegex(ValueError, 'bounds'): inspect(self.image)

    def test_crc_correct_backup_table_metadata_overlap_refused(self):
        sectors = self.image.stat().st_size // 512
        self.mutate_gpt(last=sectors-2, part=lambda t: struct.pack_into('<Q', t, 4*128+40, sectors-2))
        with self.assertRaisesRegex(ValueError, 'bounds'): inspect(self.image)

    def test_duplicate_partition_guid_refused(self):
        self.mutate_gpt(part=lambda t: t.__setitem__(slice(144,160), t[16:32]))
        with self.assertRaisesRegex(ValueError, 'duplicate'): inspect(self.image)

    def test_zero_partition_guid_refused(self):
        self.mutate_gpt(part=lambda t: t.__setitem__(slice(16,32), bytes(16)))
        with self.assertRaisesRegex(ValueError, 'zero'): inspect(self.image)

    def test_backup_header_corruption_refused(self):
        with self.image.open('r+b') as f: f.seek(-512+16,2); f.write(bytes(4))
        with self.assertRaisesRegex(ValueError, 'CRC'): inspect(self.image)

    def test_backup_table_corruption_refused(self):
        with self.image.open('r+b') as f: f.seek(-33*512,2); f.write(b'x')
        with self.assertRaisesRegex(ValueError, 'mirrored'): inspect(self.image)

    def test_second_full_readback_failure_not_success(self):
        disk = FileDisk(self.dest); real = disk.hash; counts = {}
        def corrupt(offset, length):
            counts[offset] = counts.get(offset,0)+1
            return '0'*64 if offset == 0 and counts[offset] == 3 else real(offset,length)
        with patch.object(disk,'hash',side_effect=corrupt):
            with self.assertRaisesRegex(ValueError,'full image'): self.write(disk)
        self.assertEqual(json.loads((self.root/'journal').read_text())['stage'],'writing')
        disk.unlock()

    def test_interruption_mid_gpt_relocation_resume(self):
        disk=FileDisk(self.dest); real=disk.write
        def interrupted(offset,data):
            if offset == 512 and len(data) == 512: raise OSError('relocation interruption')
            return real(offset,data)
        with patch.object(disk,'write',side_effect=interrupted):
            with self.assertRaisesRegex(OSError,'interruption'): self.write(disk)
        disk.unlock()
        self.assertEqual(json.loads((self.root/'journal').read_text())['stage'],'relocating-gpt')
        self.write()
        self.assertIn('No problems found',subprocess.check_output(['/usr/sbin/sgdisk','-v',self.dest],text=True))

    def test_release_qualification_cannot_enable_destructive_path(self):
        with patch('nvidia_flash_tools.flow.Vendor') as vendor:
            for board in ('thor','orin'):
                with self.assertRaisesRegex(ValueError,'experimental first-test risk consent'):
                    install(argparse.Namespace(engineering_hardware_qualified=True,board=board), {'hardware_qualified':True}, [])
            vendor.assert_not_called()

    def test_added_python_shadow_never_executes(self):
        (self.root/'json.py').write_text('raise Exception("attacker")')
        vendor=Vendor(self.root,'orin','1-2')
        with patch('nvidia_flash_tools.vendor.subprocess.run') as run:
            # runner captured before patch; no genuine subprocess may run.
            with self.assertRaisesRegex(ValueError,'workspace required'): vendor.run(['./flash.sh'])
            run.assert_not_called()

    def test_mutable_rootfs_and_fake_stamp_never_execute(self):
        (self.root/'rootfs').mkdir(); (self.root/'rootfs/evil').write_text('attacker')
        (self.root/'admiral-private-inputs.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'workspace required'): Vendor(self.root,'thor','1-2').run(['./flash.sh'])

    def test_package_symlink_and_external_target_refused(self):
        bl=self.root/'bootloader'; bl.mkdir()
        external=self.root/'outside'; external.write_text('evil')
        (bl/'flash.xml').symlink_to(external)
        with self.assertRaisesRegex(ValueError,'symlink'): package_hashes(self.root)

    def test_package_extra_import_file_changes_digest(self):
        bl=self.root/'bootloader'; bl.mkdir(); (bl/'flash.xml').write_text('one')
        old=package_hashes(self.root); (bl/'json.py').write_text('evil')
        self.assertNotEqual(old,package_hashes(self.root))

    def test_package_writable_input_refused(self):
        bl=self.root/'bootloader'; bl.mkdir(); f=bl/'config'; f.write_text('x'); f.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'ownership/mode'): package_hashes(self.root)

    def test_poisoned_path_env_not_forwarded(self):
        poisoned={'PATH':str(self.root),'HOME':str(self.root),'PYTHONPATH':str(self.root),
                  'LD_PRELOAD':'evil','ADB_SERVER_SOCKET':'tcp:evil:1','SSH_AUTH_SOCK':'evil'}
        with patch.dict(os.environ,poisoned), patch('nvidia_flash_tools.transport.subprocess.run',return_value=Mock(stdout=b'ok')) as run:
            self.assertEqual(execute(['/usr/bin/true']), b'ok')
        kw=run.call_args.kwargs
        self.assertEqual(kw['env']['HOME'],'/root'); self.assertEqual(kw['cwd'],'/')
        self.assertFalse(set(poisoned)-{'PATH','HOME'} & kw['env'].keys())
        with self.assertRaisesRegex(ValueError,'absolute'): execute(['true'])

    def test_ssh_ignores_poisoned_config_and_sharing(self):
        calls=[]
        ssh=SSH('usb0','1-2',self.root/'hosts',runner=lambda a,**k:calls.append(a) or b'')
        with patch.object(ssh,'bind'): ssh.shell('/bin/true')
        args=calls[0]
        self.assertEqual(args[:5], ['/usr/bin/sshpass','-p','root','/usr/bin/ssh','-T'])
        self.assertEqual(args[5:9], ['-F','/dev/null','-B','usb0'])
        self.assertIn('HostKeyAlias=admiral-orin-recovery',args)
        self.assertIn('StrictHostKeyChecking=yes',args)
        for option in ('ProxyCommand=none','ProxyJump=none','ControlMaster=no','ControlPath=none',
                       'GlobalKnownHostsFile=/dev/null','KnownHostsCommand=none','IdentityAgent=none'):
            self.assertIn(option,args)

    def test_ambient_adb_server_refused(self):
        with patch.dict(os.environ,{'ADB_SERVER_SOCKET':'tcp:attacker:5037'}):
            with self.assertRaisesRegex(ValueError,'owned private ADB server required'):
                ADB('/vendor/adb','0x123','1-2').bind()

    def fixture_graph(self,device='/dev/block/810c5b0000.spi'):
        target=self.root/'bct.bin'; target.write_bytes(bytes(512))
        index=self.root/'FileToFlash.txt'
        index.write_text(f'{device} bct bct.bin 0 1048576 1 0 0 bct 9 '+hashlib.md5(target.read_bytes()).hexdigest()+' 1\n')
        return index

    def test_source_derived_spi_graph(self):
        self.assertEqual(thor_flash_graph(self.fixture_graph())[0][0],'/dev/block/810c5b0000.spi')

    def test_thor_hidden_nvme_target_refused(self):
        index=self.fixture_graph(); line=index.read_text()
        index.write_text(line+line.replace('/dev/block/810c5b0000.spi','/dev/nvme0n1').replace(' bct ',' APP ',1))
        with self.assertRaisesRegex(ValueError,'non-SPI'): thor_flash_graph(index)

    def test_thor_hidden_ufs_target_refused(self):
        with self.assertRaisesRegex(ValueError,'non-SPI'): thor_flash_graph(self.fixture_graph('/dev/block/810c5b0000.ufshci'))

    def test_thor_escape_reference_refused(self):
        index=self.fixture_graph(); index.write_text(index.read_text().replace('bct.bin','../bct.bin'))
        with self.assertRaisesRegex(ValueError,'escapes'): thor_flash_graph(index)

    def test_thor_erase_range_refused(self):
        index=self.fixture_graph(); index.write_text(index.read_text().replace('0 1048576','67108864 1048576'))
        with self.assertRaisesRegex(ValueError,'capacity'): thor_flash_graph(index)

    def test_thor_unused_good_bytes_wrong_actual_reference_refused(self):
        original=self.root/'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
        original.parent.mkdir(parents=True); original.write_bytes(b'good-image')
        boot=self.root/'unified_flash/out/bsp_images/flash_workspace/rcm-boot'; boot.mkdir(parents=True)
        (boot/'unused.txt').write_bytes(original.read_bytes()); (boot/'rcm_blob.bin').write_bytes(b'wrong-image')
        with self.assertRaisesRegex(ValueError,'selected blob header'): inspect_thor_payload(self.root)

    def test_ram_replacement_before_generation_refused(self):
        vendor=Vendor(self.root,'thor','1-2',runner=Mock())
        with patch.object(vendor,'uid',return_value={'br_cid':'replacement','ecid':'replacement'}), patch.object(vendor,'run') as run:
            with self.assertRaisesRegex(ValueError,'changed before RAM generation'):
                vendor.ram_boot({'br_cid':'original','ecid':'original'})
            run.assert_not_called()

    def test_ram_second_board_before_generation_refused(self):
        vendor=Vendor(self.root,'thor','1-2',runner=Mock())
        usb=self.root/'usb'; usb.mkdir()
        for name in ('1-2','1-3'):
            d=usb/name; d.mkdir(); (d/'idVendor').write_text('0955')
        with patch.object(vendor,'single_rcm',side_effect=lambda:Vendor.single_rcm(vendor,usb)), patch.object(vendor,'run') as run:
            with self.assertRaisesRegex(ValueError,'exactly one'): vendor.ram_boot({'br_cid':'x','ecid':'x'})
            run.assert_not_called()

    def test_ram_replacement_before_executor_refused(self):
        vendor=Vendor(self.root,'thor','1-2',runner=Mock()); identity={'br_cid':'x','ecid':'x'}
        with patch.object(vendor,'uid',side_effect=[identity,{'br_cid':'y','ecid':'y'}]), patch('nvidia_flash_tools.vendor.inspect_thor_payload'), patch.object(vendor,'run') as run:
            with self.assertRaisesRegex(ValueError,'changed before RAM execution'): vendor.ram_boot(identity)
            self.assertEqual(run.call_count,1)
            self.assertIn('--no-flash',run.call_args.args[0])

    def test_no_recovery_pathname_write_fallback(self):
        result=subprocess.run(['/bin/bash',str(Path(__file__).resolve().parent.parent.joinpath('recovery-write.sh')),'write','/dev/nvme0n1'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('no pathname dd fallback',result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
