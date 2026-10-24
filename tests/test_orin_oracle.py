from tests.test_support import vendor_path, external_path
"""NVIDIA binary device-image oracle is NOT the legacy RAM MTD writer."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from nvidia_flash_tools import orin_firmware
class OrinOracleTests(unittest.TestCase):
    def test_actual_mkdevimages_and_actual_ram_writer_contracts(self):
        vendor=vendor_path()
        if not (vendor/'bootloader/tegradevflash_v2').is_file():self.skipTest('actual NVIDIA binaries absent')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);payload=b'vendor-file-only-no-EEPROM\0';(root/'bct.bin').write_bytes(payload)
            xml='<partition_layout version="01.00.0000"><device type="spi" instance="0" sector_size="512" num_sectors="131072"><partition name="BCT" type="boot_config_table"><allocation_policy>sequential</allocation_policy><filesystem_type>basic</filesystem_type><size>1048576</size><file_system_attribute>0</file_system_attribute><allocation_attribute>8</allocation_attribute><percent_reserved>0</percent_reserved><filename>bct.bin</filename></partition></device></partition_layout>'
            (root/'layout.xml').write_text(xml)
            (root/'dev_images').mkdir()
            for args in (['tegraparser_v2','--pt','layout.xml'],['tegraparser_v2','--pt','layout.bin','--generateflashindex','flash.idx'],['tegradevflash_v2','--pt','layout.bin','--mkdevimages','dev_images/']):
                subprocess.run([str(vendor/'bootloader'/args[0]),*args[1:]],cwd=root,check=True,capture_output=True)
            oracle=(root/'dev_images/spi_0.img').read_bytes()
            self.assertEqual(len(oracle),67108864)
            self.assertEqual(oracle[:len(payload)],payload)
            self.assertEqual(oracle[len(payload):],bytes(67108864-len(payload)))
            contract,expected=orin_firmware.plan(root/'flash.idx',root/'layout.xml',root/'layout.xml')
            # Binary mkdevimages is zero-filled and has ONE raw BCT. It is not
            # admissible as proof of legacy mtd_debug's erased-FF/64-slot output.
            self.assertNotEqual(hashlib.sha256(oracle).hexdigest(),contract['sha256'])
            controller=root/'mtd';controller.write_bytes(b'\xff'*67108864)
            script=orin_firmware.vendor_functions(vendor/'tools/kernel_flash/l4t_flash_from_kernel.sh')
            script+='\nlog_debug() { :; }; log_warning() { :; }; log_error() { echo "$*" >&2; };\n'
            script+='mtd_debug() { [ "$1" = write ]; dd if="$5" of="$2" bs=1 seek="$3" count="$4" conv=notrunc status=none; };\n'
            script+='COMMON_IMAGES_DIR='+str(root)+'\nINTERNAL=.\nekb_sn=\ndevice_sn=\ntarget_partname=\n'
            import shlex
            script+='write_to_spi_partition '+shlex.quote((root/'flash.idx').read_text().strip())+' '+str(controller)+'\n'
            subprocess.run(['/bin/bash','-euo','pipefail','-c',script],check=True,capture_output=True)
            self.assertEqual(controller.read_bytes(),expected)
            for slot in range(64):self.assertEqual(expected[slot*16384:slot*16384+len(payload)],payload)
            self.assertEqual(hashlib.sha256(controller.read_bytes()).hexdigest(),contract['sha256'])
