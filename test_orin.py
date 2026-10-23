from test_support import vendor_path, external_path
"""Source-derived R39 Orin boundaries; no hardware qualification fixtures."""
import csv
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import orin_firmware
from vendor import BOARDS, Vendor, fuse_info
from transport import SSH


class OrinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.xml = self.root/'flash.xml'
        self.xml.write_text('<partition_layout><device type="spi" instance="0" sector_size="512" num_sectors="131072"><partition name="BCT"><filename>bct.bin</filename></partition><partition name="A_cpu-bootloader"/></device></partition_layout>')
        data = b'NVDA-generated-signature-fixture\0'
        (self.root/'bct.bin').write_bytes(data)
        self.index = self.root/'flash.idx'
        self.rows = [['0','3:0:BCT','0','1048576','bct.bin',str(len(data)),'0',hashlib.sha1(data).hexdigest()],
                     ['1','3:0:A_cpu-bootloader','1048576','1048576','','0','0','']]
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        with self.index.open('w') as f:
            csv.writer(f).writerows(self.rows)

    def test_selected_ram_command_no_wrapper_or_extra_operation(self):
        from orin_recovery import command
        bl=self.root/'bootloader'; bl.mkdir()
        vendor=Vendor(self.root,'orin','1-2',runner=lambda:None)
        path=bl/'flashcmd.txt'
        path.write_text('./tegraflash.py --chip "0x23 9" --cmd rcmboot --bins "kernel boot.img"')
        argv=command(vendor,'rcmboot')
        self.assertEqual(argv[-2:],['--instance','1-2'])
        for raw in ('./tegraflash.py --chip 0x23 --cmd "rcmboot; flash"',
                    './tegraflash.py --chip 0x23 --securedev --cmd rcmboot',
                    './l4t_initrd_flash.sh --cmd rcmboot'):
            path.write_text(raw)
            with self.assertRaises(ValueError): command(vendor,'rcmboot')

    def test_exact_allowlist(self):
        self.assertEqual(BOARDS['orin'],('3701','0000','3737','0000','23'))
        self.assertEqual(BOARDS['orin-nx'],('3767','0000','3768','0000','23'))
        self.assertEqual(Vendor(self.root,'orin-nx','1-2',runner=lambda:None).alias,'jetson-orin-nano-devkit-super')

    def test_bct_full_controller_plan(self):
        contract,data = orin_firmware.plan(self.index,self.xml,self.xml)
        self.assertEqual(len(data),67108864)
        source = (self.root/'bct.bin').read_bytes()
        for offset in range(0,1048576,16384):
            self.assertEqual(data[offset:offset+len(source)],source)
        self.assertEqual(data[1048576:],b'\xff'*(67108864-1048576))
        self.assertEqual(contract['sha256'],hashlib.sha256(data).hexdigest())

    def test_reject_block_target(self):
        self.rows[1][1] = '1:0:APP'; self.save()
        with self.assertRaises(ValueError): orin_firmware.plan(self.index,self.xml,self.xml)

    def test_reject_payload_mutation(self):
        (self.root/'bct.bin').write_bytes(b'changed')
        with self.assertRaises(ValueError): orin_firmware.plan(self.index,self.xml,self.xml)

    def test_reject_traversal(self):
        self.rows[0][4] = '../bct.bin'; self.save()
        with self.assertRaises(ValueError): orin_firmware.plan(self.index,self.xml,self.xml)

    def test_reject_duplicate_and_overlap(self):
        self.rows[1][1] = '3:0:BCT'; self.save()
        with self.assertRaises(ValueError): orin_firmware.plan(self.index,self.xml,self.xml)
        self.rows[1][1] = '3:0:A_cpu-bootloader'; self.rows[1][2]='512'; self.save()
        with self.assertRaises(ValueError): orin_firmware.plan(self.index,self.xml,self.xml)

    def test_nx_fuses_require_all_orin_keys(self):
        names = ('PublicKeyHash','BootSecurityInfo','SecurityMode','ArmJtagDisable',
                 'DebugAuthentication','SwReserved','OdmLock','PkcPubkeyHash1','PkcPubkeyHash2')
        text = '\n'.join(name+': 00' for name in names)
        self.assertEqual(len(fuse_info(text,'orin-nx')),len(names))
        with self.assertRaises(ValueError): fuse_info(text.replace('PkcPubkeyHash2: 00','PkcPubkeyHash2: 01'),'orin-nx')

    def test_ssh_binary_stdin_and_explicit_hostkey(self):
        calls=[]
        def runner(argv,**kwargs):
            calls.append((argv,kwargs)); return b''
        transport=SSH('usb0','1-2',self.root/'known',runner=runner,ecid='0x123')
        with patch.object(transport,'bind'):
            transport.push(self.root/'bct.bin','/tmp/payload')
            transport.shell('/bin/true')
        for argv,kwargs in calls:
            self.assertIn('StrictHostKeyChecking=yes',argv)
            self.assertIn('HostKeyAlias=admiral-orin-recovery',argv)
            self.assertIn('-T',argv)
            self.assertEqual(argv[:3],['/usr/bin/sshpass','-p','root'])
        self.assertIn('stdin',calls[0][1])

    def test_actual_vendor_method_against_regular_file(self):
        source=vendor_path()/'tools/kernel_flash/l4t_flash_from_kernel.sh'
        if not source.is_file():
            self.skipTest('pinned vendor source not available')
        functions=orin_firmware.vendor_functions(source)
        controller=self.root/'controller'
        controller.write_bytes(b'\xff'*67108864)
        # Hardware edges only are replaced. The actual vendor method controls
        # BCT repetition, SHA1 checking and all offsets/counts.
        script=self.root/'run.sh'
        script.write_text('set -euo pipefail\n'+functions+'\n'+
            'log_debug() { :; }; log_warning() { :; }; log_error() { echo "$*" >&2; };\n'+
            'mtd_debug() { [ "$1" = write ]; dd if="$5" of="$2" bs=1 seek="$3" count="$4" conv=notrunc status=none; };\n'+
            'COMMON_IMAGES_DIR='+str(self.root)+'\nINTERNAL=.\nekb_sn=\ndevice_sn=\ntarget_partname=\n'+
            'write_to_spi_partition '+__import__('shlex').quote(', '.join(self.rows[0]))+' '+str(controller)+'\n')
        subprocess.run(['/bin/bash',script],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        contract,expected=orin_firmware.plan(self.index,self.xml,self.xml)
        self.assertEqual(controller.read_bytes(),expected)
        self.assertEqual(hashlib.sha256(controller.read_bytes()).hexdigest(),contract['sha256'])

    def test_provision_boundary_full_readback_and_corruption(self):
        from types import SimpleNamespace
        from vendor import package_hashes
        from image import sha256
        source=vendor_path()/'tools/kernel_flash/l4t_flash_from_kernel.sh'
        if not source.is_file(): self.skipTest('pinned vendor source not available')
        tree=self.root/'tree'; signed=tree/'bootloader/signed'; signed.mkdir(parents=True)
        stock=tree/'bootloader/generic/cfg/flash_t234_qspi.xml'; stock.parent.mkdir(parents=True)
        import shutil
        for original,target in ((self.index,signed/'flash.idx'),(self.xml,signed/'flash.xml.tmp'),(self.xml,stock),(self.root/'bct.bin',signed/'bct.bin')):
            shutil.copyfile(original,target)
        vendor_source=tree/'tools/kernel_flash/l4t_flash_from_kernel.sh'; vendor_source.parent.mkdir(parents=True)
        shutil.copyfile(source,vendor_source)
        for path in tree.rglob('*'):
            if not path.is_symlink(): path.chmod(path.stat().st_mode & ~0o022)
        contract,expected=orin_firmware.plan(signed/'flash.idx',signed/'flash.xml.tmp',stock)
        for corrupt in (False,True):
            calls=[]; files={}; offset=[0]
            class Transport:
                def bind(self): calls.append('bind')
                def push(self,source,target): files[target]=Path(source).read_bytes()
                def shell(self,*args):
                    if args[-1]=='br_cid': return b'BR_CID: 0x0000000000000000000000123\n'
                    if args[0]=='/bin/cat' and args[1].startswith('/sys/class/mtd/'):
                        return {'size':b'67108864','erasesize':b'65536','type':b'nor'}[Path(args[1]).name]
                    if args[0]=='/bin/mktemp': return b'/tmp/admiral-spi-abcdefgh\n'
                    if args[0]=='/usr/bin/sha256sum': return (hashlib.sha256(files[args[1]]).hexdigest()+'  '+args[1]+'\n').encode()
                    if args[0]=='/bin/bash': calls.append('erase-executor'); return b''
                    if args[0]=='/usr/sbin/mtd_debug': offset[0]=int(args[3]); return b''
                    if args[0]=='/bin/cat':
                        data=expected[offset[0]:offset[0]+4194304]
                        return bytes([data[0]^1])+data[1:] if corrupt else data
                    if args[0]=='/bin/rm': return b''
                    raise AssertionError(args)
            workspace=SimpleNamespace(root=self.root,validate=lambda:None)
            vendor=Vendor(tree,'orin','1-2',runner=lambda:None,workspace=None)
            vendor.workspace=workspace; vendor.orin_plan=contract
            vendor.approved_identity={'ecid':'0x123'}; vendor.orin_transport=Transport()
            approved=package_hashes(tree)
            if corrupt:
                with self.assertRaisesRegex(ValueError,'readback mismatch'): vendor.provision_qspi(approved)
            else:
                vendor.provision_qspi(approved)
                self.assertEqual(vendor.firmware_readback['sha256'],contract['sha256'])
                self.assertEqual(vendor.firmware_readback['size'],67108864)
            self.assertEqual(calls.count('erase-executor'),1)

    def test_vendor_function_extraction_no_main(self):
        path=self.root/'vendor.sh'
        path.write_text('function write_to_spi_partition\n{\n echo write\n}\nfunction sha1_verify\n{\n true\n}\nrm -rf /no\n')
        selected=orin_firmware.vendor_functions(path)
        self.assertIn('echo write',selected)
        self.assertNotIn('rm -rf',selected)


if __name__ == '__main__': unittest.main()
