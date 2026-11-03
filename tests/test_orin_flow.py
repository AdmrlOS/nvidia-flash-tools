from tests.test_support import vendor_path, external_path
"""Orin orchestration through real workspace/plan/vendor/readback/GPT writer.

Generation and RAM boot are device-dependent edges here; actual RAM serializer
and fresh EEPROM production boundaries are independently exercised.
"""
import argparse
import csv
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from nvidia_flash_tools import flow
from nvidia_flash_tools.image import sha256
from nvidia_flash_tools.vendor import Vendor
from nvidia_flash_tools.workspace import snapshot
from nvidia_flash_tools.writer import FileDisk
from nvidia_flash_tools import orin_firmware
from tests import test_execution
from tests import test_installer
class OrinFlowTests(unittest.TestCase):
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive
    workspace = test_execution.ExecutionTests.workspace

    def exercise(self, fault=None, board='orin'):
        fixture = test_installer.InstallerTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        from tests.test_orin_signed_cfg import fixture as signed_fixture
        w=self.workspace(); stock=signed_fixture(w, 'emmc' if fault=='emmc' else None)
        bl=w.tree/'bootloader';signed=bl/'signed'
        source=vendor_path('tools/kernel_flash/l4t_flash_from_kernel.sh')
        if not source.is_file():self.skipTest('pinned vendor source unavailable')
        target=w.tree/'tools/kernel_flash/l4t_flash_from_kernel.sh';target.parent.mkdir(parents=True);shutil.copyfile(source,target)
        (bl/'boot0.img').write_bytes(b'device-generation-edge')
        w._seal_modes();w.expected=snapshot(w.tree,os.geteuid())
        helper=self.root/'helper';helper.write_bytes(b'authenticated-helper-edge')
        disk=FileDisk(fixture.dest);physical=disk.identity();before=sha256(fixture.dest)
        native = fault is None
        if native:
            disk.unlock()
            native_root=self.root/'native';device=native_root/'sys/devices/nvme/controller';device.mkdir(parents=True)
            (device/'serial').write_text('serial\n');(device/'model').write_text('model\n')
            namespace=native_root/'sys/class/block/nvme0n1';(namespace/'holders').mkdir(parents=True)
            (namespace/'dev').write_text('259:0\n');(namespace/'device').symlink_to(device)
            (native_root/'proc/self').mkdir(parents=True);(native_root/'proc/self/mountinfo').write_text('')
            (native_root/'proc/swaps').write_text('Filename Type Size Used Priority\n')
            (native_root/'dev').mkdir();(native_root/'dev/nvme0n1').hardlink_to(fixture.dest)
            physical={'path':'/dev/nvme0n1','serial':'serial','model':'model','capacity':fixture.dest.stat().st_size,'sector':512,'major':259,'minor':0,'device':str(device)}
            executable=self.root/'native-helper'
            subprocess.run(['/usr/bin/gcc','-O2','-D_FORTIFY_SOURCE=3','-Wall','-Wextra','-Werror','-include','sys/sysmacros.h','-include','linux/fs.h',str(Path(__file__).resolve().parent.parent.joinpath('orin_native_fixture.c')),'-lcrypto','-o',str(executable)],check=True)
        identity={'br_cid':'0x80002300000000000000000000000123','ecid':'0x80002300000000000000000000000123','module':'3701-0000','carrier':'3737-0000'}
        if board=='recomputer-j40':
            from nvidia_flash_tools import carrier
            identity.update(module='3767-0000',carrier=carrier.CARRIER,carrier_rule=carrier.RULE,
                carrier_evidence=carrier.evidence(dump_returncode=1,dump_output='000000001f1e050d: E> NV3P_SERVER: Could not read eeprom for module cvb.\n',data=None,sha256=None,size=None,decoders={}))
        events=[]; files={}; offset=[0];controller=self.root/'spi';controller.write_bytes(b'\xff'*67108864)
        class RAM:
            def open_helper(self,helper,pin,observed):
                from nvidia_flash_tools.native_session import NativeSession
                self_outer.assertEqual(sha256(helper),pin)
                process=subprocess.Popen([str(executable),str(native_root),'session',str(device),str(observed['capacity'])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
                self_outer.addCleanup(lambda:process.stderr.close())
                session = NativeSession(process,observed,self.bind)
                self_outer.addCleanup(session.abort)
                return session
            def bind(self):
                if fault=='second-usb' and 'approve-firmware' in events:raise ValueError('second USB')
            def push(self,source,dest):files[dest]=Path(source).read_bytes()
            def shell(self,*args,**kwargs):
                if args[-1]=='br_cid':return b'BR_CID: 0x0000000000000000000000123\n'
                if args[0]=='/bin/cat' and args[1].startswith('/sys/class/mtd/'):
                    return {'size':b'67108864','erasesize':b'65536','type':b'nor'}[Path(args[1]).name]
                if args[0]=='/bin/mktemp':return b'/tmp/admiral-spi-abcdefgh\n'
                if args[0]=='/usr/bin/sha256sum':return (hashlib.sha256(files[args[1]]).hexdigest()+'  '+args[1]+'\n').encode()
                if args[0]=='/bin/bash':
                    events.append('erase')
                    # Run the actual production-generated vendor executor with
                    # just flash_erase/mtd_debug replaced by file-only functions.
                    local=self_outer.root/'ram';local.mkdir(exist_ok=True)
                    for name,data in files.items():(local/Path(name).name).write_bytes(data)
                    script=files[args[1]].decode().replace('/tmp/admiral-spi-abcdefgh',str(local))
                    script=script.replace('/usr/sbin/flash_erase /dev/mtd0 0 0',': # file already erased')
                    script=script.replace('/dev/mtd0',str(controller))
                    edges='mtd_debug() { [ "$1" = write ]; dd if="$5" of="$2" bs=1 seek="$3" count="$4" conv=notrunc status=none; };\n'
                    script=script.replace('COMMON_IMAGES_DIR=',edges+'COMMON_IMAGES_DIR=')
                    path=local/'run.sh';path.write_text(script)
                    subprocess.run(['/bin/bash',path],check=True,capture_output=True)
                    return b''
                if args[0]=='/usr/sbin/mtd_debug':offset[0]=int(args[3]);return b''
                if args[0]=='/bin/cat':
                    with controller.open('rb') as f:f.seek(offset[0]);data=f.read(4194304)
                    return bytes([data[0]^1])+data[1:] if fault=='raw-corrupt' else data
                if args[0]=='/bin/rm':return b''
                raise AssertionError(args)
        self_outer=self;ram=RAM();v=Vendor(w.tree,board,'1-2',workspace=w)
        def boot(vendor,observed):vendor.recovery_payload={'device-edge':True}
        probes=[identity,dict(identity,module='replaced') if fault=='replacement' else identity]
        def factory(vendor,observed):
            if fault=='hostkey':raise ValueError('host key rejected')
            return ram
        def confirm(stage,contract,pin):
            events.append('approve-'+stage)
            self.assertEqual(contract['helper_sha256'],sha256(w.root/'approved-recovery-io'))
            if board=='recomputer-j40':
                self.assertEqual(contract['physical_board']['carrier_confirmation'],'OBSERVED SEEED RECOMPUTER J401 CARRIER')
                self.assertEqual(contract['physical_board']['carrier_evidence']['outcome'],'dump-failed')
            if fault=='package-mutation' and stage=='firmware':
                (signed/'bct.bin').write_bytes(b'changed-after-approval')
            return '' if fault=='abort-'+stage else pin
        def disk_factory(*args):
            events.append('disk')
            if native:
                from nvidia_flash_tools.writer import RecoveryDisk
                return RecoveryDisk(*args)
            return disk
        args=argparse.Namespace(board=board,usb_port='1-2',helper=helper,image=fixture.image,journal=self.root/'journal',experimental_first_test=True,security_observation=lambda i:'secure-boot-disabled-observed',carrier_confirmation=lambda i:'OBSERVED SEEED RECOMPUTER J401 CARRIER')
        release={'recovery':{'helper':{'sha256':sha256(helper),'size':helper.stat().st_size,'source_sha256':sha256(Path(__file__).resolve().parent.parent.joinpath('recovery-io.c'))}},'boards':{board:{'image':{'sha256':sha256(fixture.image)}}}}
        selections=[0]
        def select(transport):
            selections[0]+=1
            return dict(physical,serial='replaced') if fault=='disk-change' and selections[0]>=3 else physical
        with patch.object(Vendor,'probe',side_effect=probes),patch.object(Vendor,'ram_boot',boot),\
                patch.object(Vendor,'usb_devnum',return_value='7'),patch.object(Vendor,'await_reenumeration'):
            def execute():return flow.orin_session(w,args,release,confirm=confirm,select_disk=select,vendor_factory=lambda *a,**k:v,transport_factory=factory,disk_factory=disk_factory,request_recovery=lambda i:events.append('recovery'))
            if fault:
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):execute()
                self.assertEqual(sha256(fixture.dest),before)
                if fault in ('emmc','hostkey','second-usb','abort-firmware'):self.assertNotIn('erase',events)
                disk.unlock()
            else:
                execute();self.assertEqual(v.firmware_readback['sha256'],sha256(controller))
                self.assertIn('No problems found',subprocess.check_output(['sgdisk','-v',fixture.dest],text=True))
                self.assertEqual(events,['approve-firmware','erase','recovery','approve-erase-nvme','disk'])

    def test_agx_flow_actual_vendor_executor_real_gpt(self):self.exercise()
    def test_nx_flow_actual_vendor_executor_real_gpt(self):self.exercise(board='orin-nx')
    def test_j40_flow_actual_vendor_executor_real_gpt(self):self.exercise(board='recomputer-j40')
    def test_disk_changed_after_ram_reboot(self):self.exercise('disk-change')
    def test_package_changed_during_approval(self):self.exercise('package-mutation')
    def test_abort_firmware(self):self.exercise('abort-firmware')
    def test_abort_disk(self):self.exercise('abort-erase-nvme')
    def test_second_usb_after_approval(self):self.exercise('second-usb')
    def test_replacement_after_recovery(self):self.exercise('replacement')
    def test_bad_hostkey_before_erase(self):self.exercise('hostkey')
    def test_corrupt_raw_qspi_stops_disk(self):self.exercise('raw-corrupt')
    def test_emmc_target_before_erase(self):self.exercise('emmc')
