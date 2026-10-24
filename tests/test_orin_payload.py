from tests.test_support import vendor_path, external_path
"""Actual T234 serializer and FINAL initrd pinning; file-only vendor inputs."""
import gzip
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from nvidia_flash_tools.orin_payload import hostkey, validate_blob


class OrinPayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tool = vendor_path('bootloader/tegrahost_v2')
        if not self.tool.is_file(): self.skipTest('actual pinned NVIDIA serializer unavailable')
        (self.root/'tegrahost_v2').symlink_to(self.tool)
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.root/'host')],check=True)
        self.boot = self.root/'boot.img'; self.make_boot()
        self.key = hostkey(self.boot)
        (self.root/'actual.img').write_bytes(self.boot.read_bytes())
        (self.root/'dtb').write_bytes(b'fixture device tree'*100)
        (self.root/'blob.xml').write_text('<file_list mode="blob"><file name="dtb" type="kernel_dtb"/><file name="actual.img" type="kernel"/></file_list>')
        self.serialize()

    def make_boot(self):
        raw = bytearray()
        for name, data in [('etc/ssh/ssh_host_ed25519_key',(self.root/'host').read_bytes()),
                           ('etc/ssh/ssh_host_ed25519_key.pub',(self.root/'host.pub').read_bytes()),('TRAILER!!!',b'')]:
            encoded = name.encode()+b'\0'
            fields = [1,0o100600,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
            raw.extend(b'070701'+b''.join(('%08x'%n).encode() for n in fields)+encoded)
            raw.extend(bytes((-len(raw))%4));raw.extend(data);raw.extend(bytes((-len(raw))%4))
        ramdisk = gzip.compress(raw,mtime=0)
        header = bytearray(2048);header[:8]=b'ANDROID!'
        struct.pack_into('<8I',header,8,2048,0,len(ramdisk),0,0,0,0,2048)
        self.boot.write_bytes(header+b'K'*2048+ramdisk)

    def serialize(self):
        subprocess.run([str(self.tool),'--chip','0x23','--generateblob','blob.xml','blob.bin'],cwd=self.root,check=True,capture_output=True)

    def test_actual_vendor_generate_blob_method(self):
        # Execute the actual source method, with only bootloader signing stubbed;
        # kernel is not in images_to_sign in this release and stays byte-exact.
        import ast
        from types import SimpleNamespace
        source=self.tool.with_name('tegraflash_impl_t234.py')
        parsed=ast.parse(source.read_text())
        cls=next(n for n in parsed.body if isinstance(n,ast.ClassDef) and n.name=='TFlashT23x_Base')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='tegraflash_generate_blob')
        namespace={'os':os,'ElementTree':__import__('xml.etree.ElementTree',fromlist=['']),
                   'values':{'--bl':'dtb','--bins':'kernel actual.img','--chip':'0x23','--chip_major':'9','--encrypt_key':None},
                   'info_print':lambda *a:None,'tegraflash_symlink':os.symlink,
                   'tegraflash_abs_path':lambda p:str(self.root/p),
                   'run_command':lambda cmd:subprocess.check_output(cmd)}
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(source),'exec'),namespace)
        obj=SimpleNamespace(bpmpdtbodm=None,exec_file=lambda tool:[str(self.tool)],tegraflash_oem_sign_file=lambda file,magic:file)
        previous=Path.cwd()
        try:
            os.chdir(self.root)
            namespace['tegraflash_generate_blob'](obj,True,'blob.bin',True)
        finally:os.chdir(previous)
        self.assertEqual(len(validate_blob(self.root,self.boot,self.key,'9')),64)

    def executor(self, fault=None):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        from nvidia_flash_tools import orin_payload
        calls=[];uid='0x80002300000000000000000000000123'
        module=SimpleNamespace(run_command=lambda command,*a,**k:calls.append(command))
        internal=SimpleNamespace(paths={'TMP':str(self.root)},values={})
        def generator(*args,**kwargs):
            module.run_command(['tegrarcm_v2','--instance','1-2','--download','bct_br','bct'])
            module.run_command(['tegrarcm_v2','--instance','1-2','--pollbl','--download','blob','blob.bin'])
            if fault=='blob':
                data=bytearray((self.root/'blob.bin').read_bytes());data[-1]^=1;(self.root/'blob.bin').write_bytes(data)
        usb=self.root/'usb';(usb/'1-2').mkdir(parents=True);(usb/'1-2/idVendor').write_text('0955')
        if fault=='usb':(usb/'1-3').mkdir();(usb/'1-3/idVendor').write_text('0955')
        real_path=Path;previous=Path.cwd();saved=list(sys.argv)
        def paths(value):return usb if str(value)=='/sys/bus/usb/devices' else real_path(value)
        real_output=subprocess.check_output
        def observed(command):
            if command[-1]=='--uid':return ('BR_CID: '+('0x80002300000000000000000000000999' if fault=='replacement' else uid)+'\n').encode()
            return real_output(command)
        # check_output for the UID only: serializer itself is subprocess.run.
        with patch.dict(sys.modules,{'tegraflash_impl_t234':module,'tegraflash_internal':internal}),patch('runpy.run_path',side_effect=generator),patch('nvidia_flash_tools.orin_payload.Path',side_effect=paths),patch('nvidia_flash_tools.orin_payload.subprocess.check_output',side_effect=observed):
            try:
                if fault:
                    with self.assertRaises(ValueError):orin_payload.selected_executor(['./tegraflash.py','--instance','1-2'],self.root,self.boot,self.key,uid)
                    self.assertEqual(calls,[])
                else:
                    orin_payload.selected_executor(['./tegraflash.py','--instance','1-2'],self.root,self.boot,self.key,uid)
                    self.assertEqual(len(calls),2)
            finally:os.chdir(previous);sys.argv=saved

    def test_executor_validates_before_deferred_downloads(self):self.executor()
    def test_executor_bad_blob_never_downloads(self):self.executor('blob')
    def test_executor_replacement_never_downloads(self):self.executor('replacement')
    def test_executor_second_usb_never_downloads(self):self.executor('usb')

    def test_actual_prepared_final_initrd_tools_and_key(self):
        boot=external_path('NVIDIA_PREPARED_BOOT_IMAGE', 'downloads/boot0.img')
        if not boot.is_file():self.skipTest('actual prepared vendor recovery image absent')
        key=hostkey(boot,require_tools=True)
        self.assertEqual(key[0],'ssh-ed25519')

    def test_required_tools_missing_is_technical_stop(self):
        with self.assertRaisesRegex(ValueError,'missing execution utility'):
            hostkey(self.boot,require_tools=True)

    def test_exact_serialized_blob(self):
        self.assertEqual(len(validate_blob(self.root,self.boot,self.key)),64)

    def test_corrupt_blob_not_good_neighbor(self):
        data=bytearray((self.root/'blob.bin').read_bytes());data[-1]^=1
        (self.root/'blob.bin').write_bytes(data)
        (self.root/'unused-good.img').write_bytes(self.boot.read_bytes())
        with self.assertRaisesRegex(ValueError,'blob bytes differ'):validate_blob(self.root,self.boot,self.key)

    def test_wrong_actual_kernel_not_good_neighbor(self):
        (self.root/'actual.img').write_bytes(b'ANDROID!wrong-kernel')
        self.serialize()
        with self.assertRaisesRegex(ValueError,'kernel differs'):validate_blob(self.root,self.boot,self.key)

    def test_final_payload_wrong_key(self):
        with self.assertRaisesRegex(ValueError,'host key differs'):validate_blob(self.root,self.boot,['ssh-ed25519','bad'])

    def test_cpio_keypair_disagrees(self):
        (self.root/'host.pub').write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogus\n')
        self.make_boot()
        with self.assertRaisesRegex(ValueError,'key pair differs'):hostkey(self.boot)

    def test_final_ramdisk_truncation(self):
        self.boot.write_bytes(self.boot.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError,'truncated'):hostkey(self.boot)
