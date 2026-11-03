import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests import test_installer
from nvidia_flash_tools.writer import FileDisk, write_image, hash_bytes
from nvidia_flash_tools.vendor import bootrom_uid, fuse_info, qspi_package, Vendor, inspect_thor_payload
from nvidia_flash_tools.transport import adb_serial, ADB, SSH
from nvidia_flash_tools.flow import experimental_authorization
from nvidia_flash_tools.image import sha256, inspect


class IntegrationTests(unittest.TestCase):
    setUp = test_installer.InstallerTests.setUp
    tearDown = test_installer.InstallerTests.tearDown
    def write(self, disk=None, board=None, retries=3):
        disk = disk or FileDisk(self.dest)
        return write_image(self.image, disk, sha256(self.image), disk.identity(),
                           board or {'ecid': 'source-derived-test'}, self.root / 'journal', retries)

    def test_chunk_real_file_gpt_relocation(self):
        expected = inspect(self.image)
        result = self.write()
        self.assertEqual(result['partitions'], expected['partitions'])
        self.assertEqual(result['table'], expected['table'])
        self.assertIn('No problems found', subprocess.check_output(['sgdisk', '-v', self.dest], text=True))
        self.assertEqual(json.loads((self.root / 'journal').read_text())['stage'], 'verified-pending-hardware-acceptance')

    def test_chunk_retry_after_failed_transfer(self):
        disk = FileDisk(self.dest)
        real = disk.write
        calls = []
        def flaky(offset, data):
            calls.append(offset)
            if len(calls) == 1:
                raise OSError('mocked transport disconnect')
            return real(offset, data)
        with patch.object(disk, 'write', side_effect=flaky):
            self.write(disk)
        self.assertEqual(calls[:2], [0, 0])

    def test_hash_mismatch_is_bounded_failure(self):
        disk = FileDisk(self.dest)
        with patch.object(disk, 'hash', return_value='0' * 64), patch.object(disk, 'write', wraps=disk.write) as write:
            with self.assertRaisesRegex(ValueError, 'chunk readback'):
                self.write(disk)
            self.assertEqual(write.call_count, 3)
        disk.unlock()

    def test_truncated_readback_fails(self):
        disk = FileDisk(self.dest)
        with patch.object(disk, 'hash', side_effect=ValueError('truncated readback')):
            with self.assertRaisesRegex(ValueError, 'truncated'):
                self.write(disk)
        disk.unlock()

    def test_device_binding_change_not_retried(self):
        disk = FileDisk(self.dest)
        identity = disk.identity()
        with patch.object(disk, 'identity', side_effect=[identity, identity, identity, {**identity, 'serial': 'replaced'}]):
            with self.assertRaisesRegex(ValueError, 'binding identity changed'):
                write_image(self.image, disk, sha256(self.image), identity, {}, self.root / 'journal')
        disk.unlock()

    def test_resume_rehash_and_changed_board_rejected(self):
        disk = FileDisk(self.dest)
        real = disk.write
        count = [0]
        def interrupted(offset, data):
            count[0] += 1
            if count[0] > 1:
                raise OSError('interrupted')
            return real(offset, data)
        with patch.object(disk, 'write', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.write(disk, retries=1)
        disk.unlock()
        resumed = FileDisk(self.dest)
        with patch.object(resumed, 'write', wraps=resumed.write) as writes:
            self.write(resumed)
            self.assertNotIn(0, [c.args[0] for c in writes.call_args_list if len(c.args[1]) == 4194304])
        replaced = FileDisk(self.dest)
        with self.assertRaisesRegex(ValueError, 'resume identity'):
            self.write(replaced, board={'ecid': 'replaced'})
        replaced.unlock()

    def test_source_hash_failure_preserves_destination(self):
        disk = FileDisk(self.dest)
        before = sha256(self.dest)
        with self.assertRaisesRegex(ValueError, 'source image'):
            write_image(self.image, disk, '0' * 64, disk.identity(), {}, self.root / 'journal')
        disk.unlock()
        self.assertEqual(sha256(self.dest), before)

    def test_ecid_base32_vendor_algorithm(self):
        self.assertEqual(adb_serial('0x123456789abcdef'), '28Q5CU4QNJFF')
        with self.assertRaises(ValueError):
            adb_serial('0x0')

    def test_source_derived_fuse_format_fail_closed(self):
        names = ['PublicKeyHash', 'BootSecurityInfo', 'SecurityMode', 'ArmJtagDisable',
                 'DebugAuthentication', 'SwReserved', 'OdmLock', 'OptInEnable']
        source = ''.join(n + ': 00000000\n' for n in names)
        self.assertEqual(len(fuse_info(source, 'thor')), len(names))
        for bad in (source.replace('PublicKeyHash: 00000000', 'PublicKeyHash: 01000000'),
                    source.replace('SecurityMode: 00000000\n', ''), source + 'unexpected format\n',
                    source + 'SecurityMode: 00000000\n'):
            with self.assertRaises(ValueError):
                fuse_info(bad, 'thor')

    def test_vendor_qspi_boundary_uses_no_flash_then_inspection(self):
        from tests import test_execution
        from tests.test_orin_signed_cfg import fixture
        case = test_execution.ExecutionTests(); case.setUp()
        self.addCleanup(case.doCleanups); self.addCleanup(case.tearDown)
        w = case.workspace(); fixture(w)
        calls = []; edge = w.runner
        def runner(argv, **kwargs):
            calls.append((argv, kwargs)); return edge(argv, **kwargs)
        w.runner = runner
        vendor = Vendor(w.tree, 'orin', '1-2', workspace=w)
        package = vendor.generate_qspi()
        self.assertIn('--no-flash', calls[0][0])
        self.assertIn('--sign', calls[0][0])
        self.assertIn('--qspi-only', calls[0][0])
        self.assertNotIn('FAB', calls[0][1]['env'])
        (w.tree/'bootloader/signed/flash.xml.tmp').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'tree changed'):
            vendor.provision_qspi(package)
        self.assertEqual(len(calls), 2)  # actual signer edge + approved SPI snapshot; flash.idx kept

    def test_remote_ecid_exact_helper_output(self):
        from nvidia_flash_tools.transport import check_remote_ecid
        from unittest.mock import Mock
        transport = Mock()
        transport.shell.return_value = b'BR_CID: 0x123456789abcdef0123456789\n'
        check_remote_ecid(transport, '0x123456789abcdef0123456789')
        transport.shell.return_value = b'0x123456789abcdef0123456789\n'
        with self.assertRaisesRegex(ValueError, 'ECID mismatch'):
            check_remote_ecid(transport, '0x123456789abcdef0123456789')

    def test_source_derived_uid_refuses_unknown_or_fused(self):
        # Not captured from hardware: exact byte positions from flash.sh.
        uid = '0x800026000000000123456789abcdef01'
        self.assertEqual(bootrom_uid('BR_CID: ' + uid + '\n', 'thor')['ecid'], '0x' + uid[9:])
        for raw in ('ECID=' + uid, 'BR_CID: ' + uid.replace('800', 'a00', 1), 'BR_CID: 0x00'):
            with self.assertRaises(ValueError):
                bootrom_uid(raw, 'thor')

    def test_qspi_xml_index_target_containment(self):
        xml = self.root / 'flash.xml'
        xml.write_text('<partition_layout><device type="spi" instance="0" sector_size="512" num_sectors="131072"><partition name="BCT" /></device></partition_layout>')
        index = self.root / 'flash.idx'
        index.write_text('0, 3:0:BCT, 0, 1048576, bct.bin, 32768, 0, abcdef\n')
        self.assertEqual(qspi_package(xml, index), ['BCT'])
        index.write_text('0, 9:0:APP, 0, 1048576, system.img, 32768, 0, abcdef\n')
        with self.assertRaisesRegex(ValueError, 'non-SPI'):
            qspi_package(xml, index)
        xml.write_text(xml.read_text().replace('type="spi"', 'type="nvme"'))
        with self.assertRaises(ValueError):
            qspi_package(xml)

    def test_adb_physical_and_serial_binding_failure(self):
        sysfs = self.root / 'usb'; device = sysfs / '1-2'
        device.mkdir(parents=True)
        (device / 'idVendor').write_text('0955')
        (device / 'serial').write_text(adb_serial('0x123'))
        calls = []
        def run(args, **kw):
            calls.append(args)
            return ('List of devices attached\n' + adb_serial('0x123') + '\tdevice\n').encode() if args[-1] == 'devices' else b''
        adb = ADB('/vendor/adb', '0x123', '1-2', run, sysfs)
        adb.shell('true')
        self.assertIn('-P', calls[-1]); self.assertIn('5038', calls[-1]); self.assertNotIn('-L', calls[-1])
        self.assertEqual(calls[-1][calls[-1].index('-s') + 1], adb_serial('0x123'))
        (device / 'serial').write_text('different')
        with self.assertRaisesRegex(ValueError, 'serial changed'):
            adb.shell('false')

    def test_transport_failure_propagates(self):
        with patch.object(ADB, 'bind'):
            adb = ADB('/vendor/adb', '0x123', '1-2', lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired('adb', 10)))
            with self.assertRaises(subprocess.TimeoutExpired):
                adb.shell('true')

    def test_ssh_interface_replacement_fails(self):
        sysfs = self.root / 'usb'; usb = sysfs / '1-2'; usb.mkdir(parents=True)
        (usb / 'idVendor').write_text('0955')
        endpoint = usb / '1-2:1.0'; endpoint.mkdir()
        netfs = self.root / 'net'; (netfs / 'usb0').mkdir(parents=True)
        (netfs / 'usb0/device').symlink_to(endpoint)
        ssh = SSH('usb0', '1-2', 'qualified-hosts', sysfs=sysfs, netfs=netfs)
        ssh.bind()
        (netfs / 'usb0/device').unlink()
        (netfs / 'usb0/device').symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, 'physical USB'):
            ssh.bind()

    def test_missing_experimental_consent_fails(self):
        from types import SimpleNamespace
        with self.assertRaisesRegex(ValueError, 'consent'):
            experimental_authorization(SimpleNamespace())

    def test_thor_payload_requires_actual_rcm_boot(self):
        original = self.root / 'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
        original.parent.mkdir(parents=True); original.write_bytes(b'fixture-not-vendor-image')
        boot = self.root / 'unified_flash/out/bsp_images/flash_workspace/rcm-boot'
        boot.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'selected Thor blob'):
            inspect_thor_payload(self.root)
        (boot / 'boot.bin').write_bytes(b'header' + original.read_bytes())
        with self.assertRaisesRegex(ValueError, 'selected Thor blob'):
            inspect_thor_payload(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
