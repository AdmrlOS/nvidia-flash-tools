from tests.test_support import vendor_path, external_path
"""Source-derived R39 Orin boundaries; no hardware qualification fixtures."""
import csv
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nvidia_flash_tools import orin_firmware
from nvidia_flash_tools.vendor import BOARDS, Vendor, fuse_info
from nvidia_flash_tools.transport import SSH


def board_hash(script, controller, scratch, remote='/tmp/admiral-spi-abcdefgh'):
    """Run the production board-side hash script on a regular file.

    Only the mtd_debug edge is replaced (by dd from the file); the loop,
    sha256sum and output format are the production script's own.
    """
    assert script.count('/usr/sbin/mtd_debug read /dev/mtd0 ') == 1, script
    edge = 'mtd_read() { dd if=' + str(controller) + ' of="$3" bs=4194304 skip=$(( $1 / 4194304 )) count=1 status=none; }\n'
    local = edge + script.replace(remote, str(scratch)).replace('/usr/sbin/mtd_debug read /dev/mtd0 ', 'mtd_read ')
    output = subprocess.run(['/bin/bash', '-c', local], check=True, capture_output=True).stdout
    return output.replace(str(scratch).encode(), remote.encode())


class OrinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.xml = self.root/'flash.xml'
        self.xml.write_text('<partition_layout><device type="spi" instance="0" sector_size="512" num_sectors="131072"><partition name="BCT"><filename>bct.bin</filename></partition><partition name="A_cpu-bootloader"></partition></device></partition_layout>')
        data = b'NVDA-generated-signature-fixture\0'
        (self.root/'bct.bin').write_bytes(data)
        self.index = self.root/'flash.idx'
        # R39.2.1 tegraparser leaves filename, length and sha1 empty for rows
        # without a payload (observed on a J4012 signed output).
        self.rows = [['0','3:0:BCT','0','1048576','bct.bin',str(len(data)),'fixed-<reserved>-1',hashlib.sha1(data).hexdigest()],
                     ['1','3:0:A_cpu-bootloader','1048576','1048576','','','fixed-<reserved>-2','']]
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        with self.index.open('w') as f:
            csv.writer(f).writerows(self.rows)

    def test_selected_ram_command_no_wrapper_or_extra_operation(self):
        from nvidia_flash_tools.orin_recovery import command
        bl=self.root/'bootloader'; bl.mkdir()
        vendor=Vendor(self.root,'orin','1-2',runner=lambda:None)
        path=bl/'flashcmd.txt'
        path.write_text('./tegraflash.py --chip "0x23 9" --cmd rcmboot --bins "kernel boot.img"')
        argv=command(vendor,'rcmboot')
        self.assertEqual(argv[-2:],['--instance','1-2'])
        for raw in ('./tegraflash.py --chip 0x23 --cmd "rcmboot; flash"',
                    './tegraflash.py --chip 0x23 --securedev --key k.pem --cmd rcmboot',
                    './l4t_initrd_flash.sh --cmd rcmboot'):
            path.write_text(raw)
            with self.assertRaises(ValueError): command(vendor,'rcmboot')
        # R39.2.1 T234 RCM boot is odmsign's pre-signed path; only there.
        path.write_text('./tegraflash.py --chip 0x23 --securedev --cmd rcmboot')
        self.assertIn('--securedev', command(vendor,'rcmboot'))
        path.write_text('./tegraflash.py --chip 0x23 --securedev --cmd "secureflash;reboot"')
        with self.assertRaisesRegex(ValueError,'secured/implicit'): command(vendor,'secureflash;reboot')

    def test_exact_allowlist(self):
        self.assertEqual(BOARDS['orin'],('3701','0000','3737','0000','23'))
        self.assertEqual(BOARDS['orin-nx'],('3767','0000','3768','0000','23'))
        self.assertEqual(Vendor(self.root,'orin-nx','1-2',runner=lambda:None).alias,'jetson-orin-nano-devkit-super')
        # reComputer J4012: same module/chip as orin-nx, but our own flash configuration
        # and no NVIDIA carrier ID (carrier rule in nvidia_flash_tools.carrier).
        self.assertEqual(BOARDS['recomputer-j40'][:2],('3767','0000'))
        self.assertEqual(BOARDS['recomputer-j40'][4],'23')
        self.assertNotEqual(BOARDS['recomputer-j40'][2:4],BOARDS['orin-nx'][2:4])
        self.assertEqual(Vendor(self.root,'recomputer-j40','1-2',runner=lambda:None).alias,'recomputer-j40-qspi')

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

    def test_empty_length_only_for_payloadless_rows(self):
        self.rows[0][5] = ''; self.save()    # a payload without a length
        with self.assertRaisesRegex(ValueError, 'partition or range'): orin_firmware.plan(self.index,self.xml,self.xml)
        self.rows[0][5] = '33'; self.rows[1][7] = 'abc'; self.save()   # half-empty row
        with self.assertRaisesRegex(ValueError, 'partition or range'): orin_firmware.plan(self.index,self.xml,self.xml)

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
            transport.shell('/bin/bash','/tmp/x/executor.sh',timeout=3600)
        for argv,kwargs in calls:
            self.assertIn('StrictHostKeyChecking=yes',argv)
            self.assertIn('HostKeyAlias=admiral-orin-recovery',argv)
            self.assertIn('-T',argv)
            self.assertEqual(argv[:3],['/usr/bin/sshpass','-p','root'])
        self.assertIn('stdin',calls[0][1])
        self.assertNotIn('timeout',calls[1][1])          # execute()'s 120 s default
        self.assertEqual(calls[2][1],{'timeout':3600})

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

    def signed_tree(self, name, board='orin'):
        """Stock + generated signed graph as generate_qspi leaves it (pinned GUIDs)."""
        import shutil
        tree=self.root/name; signed=tree/'bootloader/signed'; signed.mkdir(parents=True)
        stock=tree/orin_firmware.STOCK_XML; stock.parent.mkdir(parents=True)
        shutil.copyfile(self.xml,stock)
        (signed/'flash.xml.tmp').write_text(orin_firmware.pinned_xml(stock,board))
        for original,target in ((self.index,signed/'flash.idx'),(self.root/'bct.bin',signed/'bct.bin')):
            shutil.copyfile(original,target)
        source=tree/'tools/kernel_flash/l4t_flash_from_kernel.sh'; source.parent.mkdir(parents=True)
        source.write_text('function write_to_spi_partition\n{\n :\n}\nfunction sha1_verify\n{\n :\n}\n')
        for path in tree.rglob('*'):
            if not path.is_symlink(): path.chmod(path.stat().st_mode & ~0o022)
        contract,expected=orin_firmware.plan(signed/'flash.idx',signed/'flash.xml.tmp',stock,
                                             orin_firmware.partition_guids(board,stock))
        return tree,contract,expected

    def provision_run(self, name, board_bytes, written_bytes=None):
        """provision() against a file-backed controller; returns (result or error, calls)."""
        from types import SimpleNamespace
        from nvidia_flash_tools.vendor import package_hashes
        tree,contract,expected=self.signed_tree(name)
        controller=self.root/(name+'.spi'); controller.write_bytes(board_bytes(expected))
        scratch=self.root/(name+'.ram'); scratch.mkdir()
        calls=[]; files={}
        class Transport:
            def bind(self): calls.append(('bind',))
            def push(self,source,target): calls.append(('push',target)); files[target]=Path(source).read_bytes()
            def shell(self,*args,**kwargs):
                calls.append(args+(kwargs.get('timeout'),))
                if args[-1]=='br_cid': return b'BR_CID: 0x0000000000000000000000123\n'
                if args[0]=='/bin/cat' and args[1].startswith('/sys/class/mtd/'):
                    return {'size':b'67108864','erasesize':b'4096','type':b'nor'}[Path(args[1]).name]  # observed on a J4012
                if args[0]=='/bin/mktemp': return b'/tmp/admiral-spi-abcdefgh\n'
                if args[0]=='/usr/bin/sha256sum': return (hashlib.sha256(files[args[1]]).hexdigest()+'  '+args[1]+'\n').encode()
                if args[:2]==('/bin/bash','-c'): return board_hash(args[2],controller,scratch)
                if args[0]=='/bin/bash':
                    controller.write_bytes(written_bytes(expected)); return b''
                if args[0]=='/bin/rm': return b''
                raise AssertionError(args)
        vendor=Vendor(tree,'orin','1-2',runner=lambda:None,workspace=None)
        vendor.workspace=SimpleNamespace(root=self.root,validate=lambda:None); vendor.orin_plan=contract
        vendor.approved_identity={'ecid':'0x123'}; vendor.orin_transport=Transport()
        try:
            vendor.provision_qspi(package_hashes(tree))
            outcome=vendor.firmware_readback
        except ValueError as error:
            outcome=error
        return outcome,calls,contract

    def test_provision_identical_qspi_skips_erase_and_write(self):
        result,calls,contract=self.provision_run('same',lambda e:e)
        self.assertEqual(result['write'],'skipped-identical')
        self.assertEqual(result['sha256'],contract['sha256'])
        self.assertEqual(result['size'],67108864)
        self.assertFalse([c for c in calls if c[0]=='push'])                 # nothing staged
        self.assertFalse([c for c in calls if c[0]=='/bin/bash' and c[1].endswith('/executor.sh')])   # no erase/write
        hashes=[c for c in calls if c[:2]==('/bin/bash','-c')]
        self.assertEqual(len(hashes),1)                                       # one remote invocation
        self.assertEqual(hashes[0][-1],orin_firmware.HASH_TIMEOUT)

    def test_provision_differing_qspi_written_then_hash_verified(self):
        result,calls,contract=self.provision_run('erased',lambda e:b'\xff'*len(e),lambda e:e)
        self.assertEqual(result['write'],'written')
        self.assertEqual(result['sha256'],contract['sha256'])
        executor=[c for c in calls if c[0]=='/bin/bash' and c[1].endswith('/executor.sh')]
        self.assertEqual(len(executor),1)
        self.assertGreaterEqual(executor[0][-1],1800)   # whole-device NOR erase+write takes minutes
        order=[c[1] for c in calls if c[0]=='/bin/bash' and c[-2]!='br_cid']
        self.assertEqual(order,['-c',executor[0][1],'-c'])                    # pre-check, write, verify
        # No bulk readback over the link: no direct mtd_debug or cat of chunk data.
        self.assertFalse([c for c in calls if c[0]=='/usr/sbin/mtd_debug' or (c[0]=='/bin/cat' and not c[1].startswith('/sys/'))])

    def test_provision_post_write_mismatch_names_offset(self):
        def corrupt(e):
            data=bytearray(e); data[5*4194304+7]^=1; return bytes(data)
        error,calls,_=self.provision_run('corrupt',lambda e:b'\xff'*len(e),corrupt)
        self.assertIsInstance(error,ValueError)
        self.assertIn('mismatch at offset 20971520',str(error))
        self.assertEqual(calls[-1][:2],('/bin/rm','-rf'))                    # scratch cleaned up

    def test_board_hash_output_must_be_complete(self):
        class Transport:
            def __init__(self,output): self.output=output
            def shell(self,*args,**kwargs): return self.output
        line=lambda o:'%d %s  /tmp/admiral-spi-abcdefgh/chunk.bin\n'%(o,'0'*64)
        good=''.join(line(o) for o in range(0,67108864,4194304))
        self.assertEqual(len(orin_firmware.board_hashes(Transport(good.encode()),'/tmp/admiral-spi-abcdefgh')),16)
        for bad in (good[:-len(line(0))-10], good+line(0), good.replace(line(4194304),line(0)), good.replace('chunk.bin','other')):
            with self.assertRaises(ValueError): orin_firmware.board_hashes(Transport(bad.encode()),'/tmp/admiral-spi-abcdefgh')

    def test_unknown_spi_geometry_refused_before_staging(self):
        from types import SimpleNamespace
        for name,value in (('erasesize',b'262144'),('size',b'33554432'),('type',b'nand')):
            with self.subTest(name=name):
                geometry={'size':b'67108864','erasesize':b'4096','type':b'nor',name:value}
                calls=[]
                class Transport:
                    def bind(self): pass
                    def shell(self,*args,**kwargs):
                        if args[-1]=='br_cid': return b'BR_CID: 0x0000000000000000000000123\n'
                        if args[0]=='/bin/cat': return geometry[Path(args[1]).name]
                        calls.append(args); return b''
                tree,contract,_=self.signed_tree('tree-g-'+name)
                vendor=Vendor(tree,'orin','1-2',runner=lambda:None)
                vendor.workspace=SimpleNamespace(root=self.root,validate=lambda:None)
                vendor.orin_plan=contract; vendor.approved_identity={'ecid':'0x123'}
                with self.assertRaisesRegex(ValueError,'unexpected Orin SPI geometry/type: '+name):
                    orin_firmware.provision(vendor,Transport())
                self.assertEqual(calls,[])   # no scratch dir, hash pass, push, erase or write

    def test_pinned_xml_deterministic_unique_guid_per_partition(self):
        import uuid
        import xml.etree.ElementTree as ET
        first=orin_firmware.pinned_xml(self.xml,'recomputer-j40')
        self.assertEqual(first,orin_firmware.pinned_xml(self.xml,'recomputer-j40'))     # stable across generations
        self.assertNotEqual(first,orin_firmware.pinned_xml(self.xml,'orin-nx'))         # board-specific
        nodes=ET.fromstring(first).findall('.//partition')
        guids=[n.findtext('unique_guid').strip() for n in nodes]
        self.assertEqual(guids,[str(uuid.uuid5(orin_firmware.GUID_NAMESPACE,'recomputer-j40:'+n.get('name'))) for n in nodes])
        self.assertEqual(len(set(guids)),len(nodes))
        # Only the unique_guid lines were added to the stock bytes.
        self.assertEqual(__import__('re').sub(r'\n {12}<unique_guid> [0-9a-f-]{36} </unique_guid>','',first),self.xml.read_text())
        # plan() accepts exactly the pinned value and nothing else.
        stock=self.xml; signed=self.root/'pinned.xml'
        expected=orin_firmware.partition_guids('recomputer-j40',stock)
        for text,ok in ((first,True),(self.xml.read_text(),False),
                        (first.replace(guids[0],str(uuid.uuid4())),False),
                        (first.replace('<unique_guid>','<unique_guid>'+guids[0]+'</unique_guid><unique_guid>',1),False)):
            signed.write_text(text)
            if ok:
                orin_firmware.plan(self.index,signed,stock,expected)
            else:
                with self.assertRaisesRegex(ValueError,'unique GUID'): orin_firmware.plan(self.index,signed,stock,expected)
        signed.write_text(first)
        with self.assertRaisesRegex(ValueError,'unique GUID'): orin_firmware.plan(self.index,signed,stock)
        signed.write_text(first)    # stock already carrying GUIDs is refused
        with self.assertRaisesRegex(ValueError,'already carries'): orin_firmware.pinned_xml(signed,'orin')
        signed.write_text(self.xml.read_text().replace('></partition></device>','/></device>'))
        with self.assertRaisesRegex(ValueError,'not uniquely located'): orin_firmware.pinned_xml(signed,'orin')

    def test_flash_sh_timestamp_pinned_during_sign_and_restored(self):
        from types import SimpleNamespace
        tree=self.root/'pin'; (tree/'bootloader/generic/cfg').mkdir(parents=True)
        (tree/orin_firmware.STOCK_XML).write_text(self.xml.read_text())
        original='#!/bin/bash\n\techo "BOARDID=x"\n'+orin_firmware.VER_TIMESTAMP_SITE+'\techo "${TIMESTAMP}"\n'
        (tree/'flash.sh').write_text(original)
        vendor=SimpleNamespace(tree=tree,board='recomputer-j40',workspace=None)
        with orin_firmware.deterministic_signing(vendor) as cfg:
            self.assertEqual(cfg,orin_firmware.PINNED_XML)
            patched=(tree/'flash.sh').read_text()
            self.assertNotIn('date -R',patched); self.assertIn('\tTIMESTAMP=20260807054245\n',patched)
            out=subprocess.run(['/bin/bash',str(tree/'flash.sh')],capture_output=True,text=True,check=True).stdout
            self.assertEqual(out.split()[-1],'20260807054245')
            self.assertEqual((tree/cfg).read_text(),orin_firmware.pinned_xml(tree/orin_firmware.STOCK_XML,'recomputer-j40'))
        self.assertEqual((tree/'flash.sh').read_text(),original)
        with self.assertRaisesRegex(RuntimeError,'sign failed'):
            with orin_firmware.deterministic_signing(vendor):
                raise RuntimeError('sign failed')
        self.assertEqual((tree/'flash.sh').read_text(),original)                # restored on exception
        # The real R39.2.1 date line pins to the same constant as our replacement.
        out=subprocess.run(['/usr/bin/env','-i','TZ=Pacific/Auckland','/bin/bash','-c',
                            orin_firmware.VER_TIMESTAMP_PINNED+'echo "$VER_TIMESTAMP|$TIMESTAMP"'],capture_output=True,text=True,check=True).stdout
        self.assertEqual(out.strip(),'Fri, 07 Aug 2026 05:42:45 +0000|20260807054245')
        for broken in (original.replace('date -R','date -u -R'),original+orin_firmware.VER_TIMESTAMP_SITE):
            (tree/'flash.sh').write_text(broken)
            with self.assertRaisesRegex(ValueError,'timestamp site changed'):
                with orin_firmware.deterministic_signing(vendor): pass
            self.assertEqual((tree/'flash.sh').read_text(),broken)

    def test_pinned_timestamp_matches_vendor_flash_sh(self):
        source=vendor_path()/'flash.sh'
        if not source.is_file(): self.skipTest('pinned vendor source not available')
        self.assertEqual(source.read_text().count(orin_firmware.VER_TIMESTAMP_SITE),1)
        stock=vendor_path()/orin_firmware.STOCK_XML
        pinned=orin_firmware.pinned_xml(stock,'recomputer-j40')
        self.assertEqual(pinned.count('<unique_guid>'),len(orin_firmware.partition_guids('recomputer-j40',stock)))

    def test_vendor_function_extraction_no_main(self):
        path=self.root/'nvidia_flash_tools.vendor.sh'
        path.write_text('function write_to_spi_partition\n{\n echo write\n}\nfunction sha1_verify\n{\n true\n}\nrm -rf /no\n')
        selected=orin_firmware.vendor_functions(path)
        self.assertIn('echo write',selected)
        self.assertNotIn('rm -rf',selected)

class DiskGuidPinTests(unittest.TestCase):
    def gpt(self, disk):
        import struct, zlib, uuid
        entries = bytearray(16384); entries[16:32] = uuid.uuid4().bytes_le
        header = bytearray(512)
        header[0:8] = b'EFI PART'; struct.pack_into('<II', header, 8, 0x10000, 92)
        struct.pack_into('<QQQQ', header, 24, 131071, 1, 34, 131038)
        header[56:72] = disk.bytes_le
        struct.pack_into('<QIII', header, 72, 131039, 128, 128, zlib.crc32(entries))
        struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
        return bytes(entries + header)

    def test_disk_guid_pinned_crc_valid_and_index_rewritten(self):
        import struct, tempfile, uuid, zlib
        from nvidia_flash_tools.orin_firmware import pin_disk_guid, disk_guid, GPT_FILES
        results = []
        for _ in range(2):                      # two "sessions", different random disk GUIDs
            with tempfile.TemporaryDirectory() as tmp:
                signed = Path(tmp)
                rows = []
                for i, name in enumerate(GPT_FILES):
                    data = self.gpt(uuid.uuid4()); (signed / name).write_bytes(data)
                    rows.append('%d, 3:0:%s, 0, 65536, %s, 16896, fixed-<reserved>-0, %s\n'
                                % (i, name.split('.')[0], name, hashlib.sha1(data).hexdigest()))
                (signed / 'flash.idx').write_text('0, 3:0:BCT, 0, 262144, br_bct_BR.bct, 4096, fixed-<reserved>-0, ' + 'a' * 40 + '\n' + ''.join(rows))
                pin_disk_guid(signed, 'recomputer-j40')
                for line in (signed / 'flash.idx').read_text().splitlines()[1:]:
                    f = [x.strip() for x in line.split(',')]
                    data = (signed / f[4]).read_bytes()
                    self.assertEqual(hashlib.sha1(data).hexdigest(), f[7])
                    self.assertEqual(data[16440:16456], disk_guid('recomputer-j40').bytes_le)
                    header = bytearray(data[16384:16476]); stored = struct.unpack_from('<I', header, 16)[0]
                    header[16:20] = bytes(4)
                    self.assertEqual(zlib.crc32(header), stored)
                    results.append(data[16384 + 56:16384 + 72])
                self.assertTrue((signed / 'flash.idx').read_text().splitlines()[0].endswith('a' * 40))
        self.assertEqual(len(set(results)), 1)

    def test_disk_guid_pin_refuses_unknown_layout_or_index(self):
        import tempfile, uuid
        from nvidia_flash_tools.orin_firmware import pin_disk_guid, GPT_FILES
        with tempfile.TemporaryDirectory() as tmp:
            signed = Path(tmp)
            for name in GPT_FILES:
                (signed / name).write_bytes(self.gpt(uuid.uuid4()))
            (signed / 'flash.idx').write_text('')        # present but unlisted: not trusted
            with self.assertRaisesRegex(ValueError, 'not uniquely found'):
                pin_disk_guid(signed, 'recomputer-j40')
            (signed / GPT_FILES[0]).write_bytes(bytes(16896))
            with self.assertRaisesRegex(ValueError, 'layout'):
                pin_disk_guid(signed, 'recomputer-j40')
        with tempfile.TemporaryDirectory() as tmp:
            signed = Path(tmp); (signed / 'flash.idx').write_text('')
            pin_disk_guid(signed, 'recomputer-j40')     # graph without secondary GPTs: no-op
            (signed / 'flash.idx').write_text('1, 3:0:secondary_gpt, 0, 65536, %s, 16896, x, %s\n' % (GPT_FILES[0], 'b' * 40))
            with self.assertRaisesRegex(ValueError, 'missing'):
                pin_disk_guid(signed, 'recomputer-j40')  # listed but absent


if __name__ == '__main__': unittest.main()
