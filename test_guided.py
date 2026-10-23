"""Guided UI tests: fake host/device edges only; no USB discovery."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import flow
import image

class GuidedTests(unittest.TestCase):
    def test_install_consent_precedes_download_and_discovery(self):
        import thor
        with patch('builtins.input', return_value='no'), patch('thor.bundle', side_effect=AssertionError('bundle before consent')), patch('thor.recovery_port', side_effect=AssertionError('discovery before consent')):
            with self.assertRaisesRegex(ValueError, 'consent declined'):
                thor.main(['install'])

    def test_bundle_requires_independent_pin_and_checks_each_byte(self):
        import thor
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = b'source'; (root/'thor.py').write_bytes(source)
            release = {'schema': 1, 'classification': 'engineering-test-keys', 'nvidia': {'version': '39.2.1'}}
            (root/'engineering-release.json').write_text(json.dumps(release))
            (root/'recovery-io').write_bytes(b'helper')
            manifest = {'recovery': {'helper': {'sha256': image.sha256(root/'recovery-io'), 'size': 6}}, 'schema': 1, 'authorization': None, 'hardware_qualified': False,
                        'artifacts': {'thor.py': {'sha256': image.sha256(root/'thor.py'), 'size': len(source)}},
                        'engineering_release_sha256': image.sha256(root/'engineering-release.json')}
            (root/'engineering-manifest.json').write_text(json.dumps(manifest))
            pin = image.sha256(root/'engineering-manifest.json')
            self.assertEqual(thor.bundle(root, pin), release)
            with self.assertRaisesRegex(ValueError, 'independent'): thor.bundle(root, '0'*64)
            (root/'recovery-io').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'mismatch'): thor.bundle(root, pin)
            (root/'recovery-io').write_bytes(b'helper')
            (root/'thor.py').write_bytes(b'change')
            with self.assertRaisesRegex(ValueError, 'mismatch'): thor.bundle(root, pin)

    def test_recovery_detection_requires_exactly_one_endpoint(self):
        import thor
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaisesRegex(ValueError, 'exactly one'): thor.recovery_port(root)
            d = root/'1-2'; d.mkdir(); (d/'idVendor').write_text('0955'); (d/'idProduct').write_text('unknown')
            # NVIDIA identity alone must not be advertised as Thor recovery.
            with self.assertRaisesRegex(ValueError, 'unverified'): thor.recovery_port(root)

    def test_human_approval_retains_backend_digest_without_typing_it(self):
        import thor
        contract = {'physical_board': {'ecid': '0x123'}, 'nvme': {'serial': 'exact-disk', 'capacity': 4096}}
        with patch('builtins.input', return_value='ERASE NVME'), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(thor.approval('erase-nvme', contract, 'a'*64), 'a'*64)
        self.assertIn('exact-disk', out.getvalue()); self.assertIn('0x123', out.getvalue())
        with patch('builtins.input', return_value='yes'), contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(thor.approval('erase-nvme', contract, 'a'*64), 'a'*64)

    def test_offline_check_never_discovers_or_requires_root(self):
        import thor
        release = {'boards': {'thor': {'image': {'name': 'image'}}}}
        with patch('thor.bundle', return_value=release), patch('builtins.input', return_value='/ordinary/image'), patch('thor.prerequisites', return_value=['missing packages; approved command not run']), patch('thor.verify_image') as verify, patch('thor.recovery_port', side_effect=AssertionError('USB')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(thor.main(['check', '--bundle-pin', 'a'*64]), 0)
        verify.assert_called_once()

    def test_ready_wait_retries_only_same_topology_and_is_bounded(self):
        from transport import ADB, adb_serial
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); d = root/'1-2'; d.mkdir()
            (d/'idVendor').write_text('0955'); (d/'serial').write_text(adb_serial('0x123'))
            clock = [0.]; calls = []
            def sleep(n): clock[0] += n
            def run(argv, **kw):
                calls.append(kw['timeout'])
                return b'List of devices attached\n' + (b'' if len(calls) == 1 else b'93\tdevice\n')
            adb = ADB('/vendor/adb', '0x123', '1-2', runner=run, sysfs=root)
            with patch('transport.time.monotonic', side_effect=lambda: clock[0]), patch('transport.time.sleep', side_effect=sleep):
                adb.wait_ready(timeout=1)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(0 < n <= 1 for n in calls))
                (d/'serial').write_text('changed')
                with self.assertRaisesRegex(ValueError, 'serial changed'): adb.wait_ready(timeout=1)
                (d/'serial').write_text(adb_serial('0x123'))
                adb.run = lambda *a, **k: b'List of devices attached\n'
                with self.assertRaisesRegex(TimeoutError, 'ready'): adb.wait_ready(timeout=1)
                self.assertLessEqual(clock[0], 1.25)

    def test_guided_single_disk_avoids_extra_erase_prompt(self):
        transport = Mock()
        values = {'dev': b'259:0', 'device/serial': b'disk-serial', 'device/model': b'model', 'size': b'100', 'queue/logical_block_size': b'512'}
        def shell(*args):
            if args[0] == '/bin/sh': return b'/sys/class/block/nvme0n1\n'
            if args[0] == '/bin/readlink': return b'/devices/pci/nvme/nvme0/nvme0n1'
            return values[args[1].split('/nvme0n1/')[1]]
        transport.shell.side_effect = shell
        with patch('builtins.input', side_effect=AssertionError('second destructive prompt')), contextlib.redirect_stdout(io.StringIO()):
            disk = flow.select_recovery_disk(transport, choose_single=True)
        self.assertEqual(disk['serial'], 'disk-serial')

if __name__ == '__main__': unittest.main()
