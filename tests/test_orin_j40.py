"""Seeed reComputer J40/J4012 (recomputer-j40): selector, carrier rule, vendor inputs, approval.

Offline only. No J401 hardware output has been captured: the cvb fixtures below
are synthetic stand-ins for the *classes* of outcome in carrier.CVB_TABLE and
make no claim about what the real board returns.
"""
from tests.test_support import vendor_path
import argparse
import contextlib
import copy
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nvidia_flash_tools import carrier, flow, orin, thor, vendor_inputs
from nvidia_flash_tools.image import sha256
from nvidia_flash_tools.vendor import ALIASES, BOARDS, Vendor, package_hashes
from nvidia_flash_tools.workspace import Workspace, snapshot, tolerable_failure
from tests import test_execution

ROOT = Path(__file__).resolve().parent.parent
RELEASE = json.loads((ROOT/'release.json').read_text())
UID = b'BR_CID: 0x80002300000000000000000000000123\n'
ECID = '0x80002300000000000000000000000123'
FUSE_NAMES = ('PublicKeyHash', 'BootSecurityInfo', 'SecurityMode', 'ArmJtagDisable', 'DebugAuthentication',
              'SwReserved', 'OdmLock', 'PkcPubkeyHash1', 'PkcPubkeyHash2')
DECODE = {'nvidia-3768': {'-i': '3768', '-k': '0000'}, 'nvidia-3509': {'-i': '3509', '-k': '0000'},
          'nvidia-3737': {'-i': '3737', '-k': '0000'}, 'nvidia-4071': {'-i': '4071', '-k': '0000'},
          'nvidia-other': {'-i': '1234', '-k': '0001'}, 'sku-only': {'-k': '0000'},
          'text-garbage': {'-i': 'SEEED', '-k': 'J401'}}


# Real MB2 answer observed on a J4012 (R39.2.1), before NVIDIA's broken retry.
MB2_LOG = '[   1.4753 ] 000000001f1e050d: E> NV3P_SERVER: Could not read eeprom for module cvb.\n'

class SelectorTests(unittest.TestCase):
    def test_boards_alias_and_orin_nx_unchanged(self):
        self.assertEqual(BOARDS['recomputer-j40'][:2], ('3767', '0000'))
        self.assertEqual(BOARDS['recomputer-j40'][4], '23')
        # The carrier fields can never equal a chkbdinfo decode of an NVIDIA board.
        self.assertFalse(BOARDS['recomputer-j40'][2].isdigit())
        self.assertEqual(ALIASES['recomputer-j40'], 'recomputer-j40-qspi')
        self.assertEqual(Vendor(ROOT, 'recomputer-j40', '1-2', runner=lambda: None).alias, 'recomputer-j40-qspi')
        self.assertNotIn('jetson', Vendor(ROOT, 'recomputer-j40', '1-2', runner=lambda: None).alias)
        self.assertEqual(BOARDS['orin-nx'], ('3767', '0000', '3768', '0000', '23'))
        self.assertEqual(Vendor(ROOT, 'orin-nx', '1-2', runner=lambda: None).alias, 'jetson-orin-nano-devkit-super')
        self.assertEqual(Vendor(ROOT, 'orin', '1-2', runner=lambda: None).alias, 'jetson-agx-orin-devkit')
        self.assertEqual(Vendor(ROOT, 'thor', '1-2', runner=lambda: None).alias, 'jetson-agx-thor-devkit')

    def test_orin_entrypoint_parses_board(self):
        with patch('nvidia_flash_tools.thor.main', return_value=0) as main:
            self.assertEqual(orin.main(['check', '--board', 'recomputer-j40', '--bundle-pin', 'a'*64]), 0)
        main.assert_called_once_with(['check', '--board', 'recomputer-j40', '--bundle-pin', 'a'*64])
        with patch('nvidia_flash_tools.thor.main') as main, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                orin.main(['check', '--board', 'recomputer-j41'])
        main.assert_not_called()

    def test_thor_main_accepts_selector_and_checks_that_boards_image(self):
        release = {'boards': {'recomputer-j40': {'image': {'name': 'admiral-recomputer-j40.img'}}}}
        with patch('nvidia_flash_tools.thor.bundle', return_value=release), patch('builtins.input', return_value='/ordinary/image'), \
                patch('nvidia_flash_tools.thor.prerequisites', return_value=[]), patch('nvidia_flash_tools.thor.verify_image') as verify, \
                patch('nvidia_flash_tools.thor.recovery_port', side_effect=AssertionError('USB')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(thor.main(['check', '--board', 'recomputer-j40', '--bundle-pin', 'a'*64]), 0)
        self.assertEqual(verify.call_args[0][1:], (release, 'recomputer-j40'))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            thor.main(['check', '--board', 'recomputer-j41'])

    def test_install_entrypoint_parses_board(self):
        from nvidia_flash_tools import install
        with patch.object(sys, 'argv', ['install.py', 'check', '--board', 'recomputer-j40', '--manifest-sha256', '0'*64]):
            with self.assertRaisesRegex(ValueError, 'differs'):
                install.main()
        with patch.object(sys, 'argv', ['install.py', 'check', '--board', 'recomputer-j41', '--manifest-sha256', '0'*64]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                install.main()

    def test_release_record(self):
        record = RELEASE['boards']['recomputer-j40']
        self.assertEqual(record['module'], '3767-0000')
        self.assertEqual(record['vendor_board'], 'recomputer-j40-qspi')
        self.assertIsNone(record['download_url'])
        self.assertEqual(record['image'], {'name': 'admiral-recomputer-j40.img', 'size': 3699412992,
                                           'sha256': '52c2ca1f08f2814f5267c286dd79f2d0ad730cc0ff356ca0129c739f3ed6d0ec'})
        self.assertEqual(record['carrier_rule'], carrier.RULE)
        self.assertEqual(RELEASE['boards']['orin-nx']['vendor_board'], 'jetson-orin-nano-devkit-super')
        self.assertIs(RELEASE['hardware_qualified'], False)

    def test_vendored_flash_dtbs_have_no_merged_camera_overlay(self):
        # The flash recipe must carry Seeed's base DTBs; the camera overlay is
        # merged only into the Admiral image's boot-slot DTB.
        root = Path(__file__).resolve().parent.parent / 'vendor-inputs/recomputer-j40/dtb'
        dtbs = sorted(root.glob('*.dtb'))
        self.assertEqual(len(dtbs), 4)
        for dtb in dtbs:
            self.assertNotIn(b'rbpcv2_imx219_a@10', dtb.read_bytes(), dtb.name)

    def test_image_record_rejects_another_boards_image(self):
        from nvidia_flash_tools.install import check_artifact
        other = RELEASE['boards']['orin-nx']['image']
        self.assertNotEqual(other['sha256'], RELEASE['boards']['recomputer-j40']['image']['sha256'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'admiral-recomputer-j40.img'
            path.write_bytes(b'not the pinned image')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                check_artifact(path, RELEASE['boards']['recomputer-j40']['image'])


class VendorPinTests(unittest.TestCase):
    def test_repo_inputs_match_their_pins_and_are_packaged(self):
        inputs = vendor_inputs.load(RELEASE, 'recomputer-j40', ROOT)
        self.assertEqual(len(inputs['dtbs']), 4)
        self.assertEqual(len(inputs['dtbos']), 1)
        self.assertEqual(inputs['mb2']['stock_sha256'], '42572d28b0dec865e9e0db3a6c04c03e77dd1c06fce80d76f45c3a12f2ed096b')
        self.assertEqual(inputs['mb2']['patched_sha256'], '42f96bb96cb6825c575aa6242f77a1cec4f571055d8b4e2d789991d409fe2f73')
        import package
        record = RELEASE['boards']['recomputer-j40']['vendor_inputs']
        pinned = [record['mb2_patch']['patch'], record['config'], record['recovery_config'],
                  record['sample_rootfs_members'], *record['dtbs'], *record['dtbos']]
        self.assertTrue({item['path'] for item in pinned} <= set(package.FILES))
        for name in ('carrier', 'vendor_inputs'):
            self.assertIn('nvidia_flash_tools/' + name + '.py', package.FILES)
        self.assertIn('tests/test_orin_j40.py', package.FILES)

    def test_one_flipped_byte_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)/'bundle'
            import shutil
            shutil.copytree(ROOT/'vendor-inputs', bundle/'vendor-inputs')
            vendor_inputs.load(RELEASE, 'recomputer-j40', bundle)
            target = bundle/RELEASE['boards']['recomputer-j40']['vendor_inputs']['dtbs'][0]['path']
            data = bytearray(target.read_bytes())
            data[-1] ^= 1
            target.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                vendor_inputs.load(RELEASE, 'recomputer-j40', bundle)

    def test_real_patch_against_real_stock_when_available(self):
        stock = vendor_path(vendor_inputs.MB2_TARGET)
        if not stock.is_file():
            self.skipTest('pinned NVIDIA vendor tree not available')
        record = RELEASE['boards']['recomputer-j40']['vendor_inputs']['mb2_patch']
        self.assertEqual(sha256(stock), record['stock_sha256'])
        patch_text = (ROOT/record['patch']['path']).read_text()
        patched = vendor_inputs.apply_unified_diff(stock.read_text(), patch_text, vendor_inputs.MB2_TARGET)
        self.assertEqual(hashlib.sha256(patched.encode()).hexdigest(), record['patched_sha256'])
        self.assertIn('cvb_eeprom_read_size = <0>;', patched)
        self.assertEqual(patched.count('<0x100>'), stock.read_text().count('<0x100>') - 1)


class CvbTableTests(unittest.TestCase):
    def test_single_documented_table(self):
        self.assertEqual({name: accepted for name, accepted, _ in carrier.CVB_TABLE},
                         {'dump-failed': True, 'dump-error': False, 'unexpected-size': False, 'nvidia-carrier-decoded': False,
                          'blank-zero': True, 'blank-ff': True, 'undecodable': True})
        self.assertEqual(carrier.ACCEPTED, {'dump-failed', 'blank-zero', 'blank-ff', 'undecodable'})
        self.assertEqual(carrier.CONFIRMATION, 'OBSERVED SEEED RECOMPUTER J401 CARRIER')
        self.assertTrue({'3768', '3509', '3737', '4071'} <= set(carrier.NVIDIA_CARRIER_IDS))
        self.assertEqual(carrier.PINNED_CVB_SHA256, frozenset())
        reference = (ROOT/'docs/reference.md').read_text()
        for name, _, _ in carrier.CVB_TABLE:
            self.assertIn('`' + name + '`', reference)
        self.assertIn(carrier.CONFIRMATION, reference)

    def record(self, outcome_data, rc=0, decoded=None, output=''):
        decoders = {flag: (0, value) if value is not None else (1, 'chkbdinfo: invalid')
                    for flag, value in (decoded or {}).items()}
        digest = hashlib.sha256(outcome_data).hexdigest() if isinstance(outcome_data, bytes) else None
        size = len(outcome_data) if isinstance(outcome_data, bytes) else None
        return carrier.evidence(dump_returncode=rc, dump_output=output, data=outcome_data, sha256=digest,
                                size=size, decoders=decoders)

    def test_accepted_outcomes(self):
        cases = {'dump-failed': self.record(None, rc=1, output=MB2_LOG),
                 'blank-zero': self.record(b'\0'*256, decoded={'-i': None, '-k': None}),
                 'blank-ff': self.record(b'\xff'*256, decoded={'-i': None, '-k': None}),
                 'undecodable': self.record(bytes(range(256)), decoded={'-i': None, '-k': None})}
        for outcome, record in cases.items():
            with self.subTest(outcome):
                self.assertEqual(record['outcome'], outcome)
                self.assertIs(carrier.check_evidence(record), record)
        self.assertEqual(cases['dump-failed']['dump_returncode'], 1)
        self.assertIsNone(cases['dump-failed']['cvb_sha256'])
        self.assertEqual(cases['blank-zero']['cvb_sha256'], hashlib.sha256(b'\0'*256).hexdigest())
        self.assertEqual(cases['undecodable']['decoded'], {'id': None, 'sku': None})
        # a non-NVIDIA-format decode is recorded verbatim and still accepted
        text = self.record(bytes(range(256)), decoded={'-i': 'SEEED', '-k': 'J401'})
        self.assertEqual((text['outcome'], text['decoded']), ('undecodable', {'id': 'SEEED', 'sku': 'J401'}))
        # ... and a blank file whose decoder printed something is not "silently blank"
        loud = self.record(b'\0'*256, decoded={'-i': 'SEEED', '-k': None})
        self.assertEqual(loud['outcome'], 'undecodable')
        self.assertEqual(cases['dump-failed']['mb2_answer'], carrier.MB2_NO_CVB)
        # without MB2's own answer a failed dump is an unexplained error, refused
        for rc, output in ((0, ''), (1, 'Error: Invalid option --chip\n'), (1, 'Error: Return value 8\n')):
            with self.subTest(rc=rc, output=output):
                record = self.record(None, rc=rc, output=output)
                self.assertEqual((record['outcome'], record['mb2_answer']), ('dump-error', None))
                with self.assertRaisesRegex(ValueError, 'cvb outcome dump-error'):
                    carrier.check_evidence(record)

    def test_refused_outcomes(self):
        for ident in ('3768', '3509', '3737', '4071', '1234'):
            for decoded in ({'-i': ident, '-k': '0000'}, {'-i': ident, '-k': None}, {'-i': None, '-k': ident}):
                with self.subTest(ident=ident, decoded=decoded):
                    record = self.record(bytes(range(256)), decoded=decoded)
                    self.assertEqual(record['outcome'], 'nvidia-carrier-decoded')
                    with self.assertRaisesRegex(ValueError, 'carrier refused.*nvidia-carrier-decoded'):
                        carrier.check_evidence(record)
        named = self.record(bytes(range(256)), decoded={'-i': '3768', '-k': '0000'})
        self.assertIn('3768', named['reason'])
        for data in (b'\0'*255, b'\xff'*257, False):
            record = self.record(data)
            self.assertEqual(record['outcome'], 'unexpected-size')
            with self.assertRaisesRegex(ValueError, 'unexpected-size'):
                carrier.check_evidence(record)

    def test_check_never_trusts_a_stored_flag_or_other_rule(self):
        record = self.record(bytes(range(256)), decoded={'-i': '3768', '-k': '0000'})
        record['accepted'] = True
        with self.assertRaises(ValueError):
            carrier.check_evidence(record)
        accepted = self.record(b'\0'*256)
        for broken in (dict(accepted, rule='other'), dict(accepted, outcome='made-up'), None, {}):
            with self.assertRaises(ValueError):
                carrier.check_evidence(broken)

    def test_pinned_capture_tightens_only_undecodable(self):
        record = self.record(bytes(range(256)))
        with patch.object(carrier, 'PINNED_CVB_SHA256', frozenset({'a'*64})):
            with self.assertRaisesRegex(ValueError, 'pinned'):
                carrier.check_evidence(record)
            carrier.check_evidence(self.record(None, rc=1, output=MB2_LOG))
        with patch.object(carrier, 'PINNED_CVB_SHA256', frozenset({record['cvb_sha256']})):
            carrier.check_evidence(record)

    def identity(self, **changes):
        identity = {'br_cid': ECID, 'ecid': ECID, 'module': '3767-0000', 'carrier': carrier.CARRIER,
                    'carrier_rule': carrier.RULE, 'carrier_evidence': self.record(b'\0'*256)}
        identity.update(changes)
        return identity

    def test_confirmation_binding(self):
        identity = carrier.bind_confirmation(self.identity(), carrier.CONFIRMATION)
        self.assertEqual(identity['carrier_confirmation'], carrier.CONFIRMATION)
        carrier.validate_bound(identity)
        for typed in ('', 'yes', 'observed seeed recomputer j401 carrier', carrier.CONFIRMATION + ' ',
                      'OBSERVED SECURE BOOT DISABLED', None):
            with self.subTest(typed=typed):
                with self.assertRaisesRegex(ValueError, 'confirmation'):
                    carrier.bind_confirmation(self.identity(), typed)
        refused = self.record(bytes(range(256)), decoded={'-i': '3768', '-k': '0000'})
        with self.assertRaisesRegex(ValueError, 'refused'):
            carrier.bind_confirmation(self.identity(carrier_evidence=refused), carrier.CONFIRMATION)
        with self.assertRaisesRegex(ValueError, 'carrier rule'):
            carrier.bind_confirmation(self.identity(carrier='3768-0000'), carrier.CONFIRMATION)
        # approval guard: evidence present but no typed confirmation
        with self.assertRaisesRegex(ValueError, 'confirmation'):
            carrier.validate_bound(self.identity())
        carrier.validate_bound({'carrier': '3768-0000', 'module': '3767-0000'})

    def test_stable_ignores_only_volatile_and_policy_fields(self):
        a = carrier.bind_confirmation(self.identity(), carrier.CONFIRMATION)
        a['uefi_policy'] = 'secure-boot-disabled-observed'
        b = self.identity()
        b['carrier_evidence']['volatile'] = {'dump_output_tail': 'different timestamps'}
        self.assertEqual(carrier.stable(a), carrier.stable(b))
        c = self.identity()
        c['carrier_evidence']['cvb_sha256'] = 'b'*64
        self.assertNotEqual(carrier.stable(a), carrier.stable(c))
        self.assertIn('volatile', a['carrier_evidence'])


class ProbeBase(unittest.TestCase):
    board = 'recomputer-j40'

    def setUp(self):
        self.umask = os.umask(0o022)
        self.addCleanup(os.umask, self.umask)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = Workspace(self.root/'session', owner=os.geteuid())
        self.addCleanup(self.workspace.close)
        self.tree = self.workspace.tree
        (self.tree/'bootloader').mkdir(parents=True)
        (self.tree/'flash.sh').write_text('fixture')
        self.workspace._seal_modes()
        self.workspace.expected = snapshot(self.tree, os.geteuid())
        self.workspace.runner = self.edge
        self.calls, self.cvb, self.cvm, self.partial, self.rcm = [], 'blank-zero', ('3767', '0000'), False, 0
        self.vendor = Vendor(self.tree, self.board, '1-2', workspace=self.workspace)

    def cvb_bytes(self):
        return {'blank-zero': b'\0'*256, 'blank-ff': b'\xff'*256, 'short': b'x'*255}.get(
            self.cvb, bytes(range(256)) if self.cvb in ('garbage', 'text-garbage') else b'cvb'.ljust(256, b'\0'))

    def edge(self, argv, **kwargs):
        self.calls.append(list(argv))
        bl = self.tree/'bootloader'
        done = lambda rc=0, out=b'': subprocess.CompletedProcess(argv, rc, out)
        if argv[0] == './tegrarcm_v2':
            self.rcm += 1
            if getattr(self, 'applet', False):
                return done(8)  # boot ROM unreachable while the MB2 applet runs
            return done(0, UID.replace(b'123', b'999') if getattr(self, 'swap_after', None) and self.rcm > self.swap_after else UID)
        if argv[0] == './flash.sh':
            self.assertIn(self.vendor.alias, argv)
            self.assertIn('--read-info', argv)
            (bl/'readinfocmd.txt').write_text('rm cvm.bin;\n./tegraflash.py --chip "0x23 9" --cmd "readfuses fuse_t234.bin read.xml; dump eeprom cvm cvm.bin; dump try_custinfo custinfo_out.bin; reboot recovery";\n')
            return done()
        if argv[0] == '/usr/bin/python3':
            self.assertEqual(argv[-2:], ['--instance', '1-2'])
            self.applet = True  # tegraflash boots (or reuses) the MB2 applet
            for part in [shlex.split(p) for p in argv[argv.index('--cmd')+1].split(';') if p.strip()]:
                if part[0] == 'readfuses':
                    (bl/'fuse_t234.bin').write_text(''.join(n + ': 00\n' for n in FUSE_NAMES))
                elif part[:3] == ['dump', 'eeprom', 'cvm']:
                    (bl/part[-1]).write_bytes(b'cvm'.ljust(256, b'\0'))
                elif part[:3] == ['dump', 'eeprom', 'cvb']:
                    if self.cvb == 'dump-failed':
                        if self.partial:
                            (bl/part[-1]).write_bytes(b'partial')
                        return done(1, (('[ %.4f ] tegrarcm_v2 --oem platformdetails eeprom cvb\n' % (len(self.calls)/7)) + MB2_LOG +
                                       'Error: Invalid option --chip\nError: Return value 4\n').encode())
                    (bl/part[-1]).write_bytes(self.cvb_bytes())
                elif part[0] == 'reboot':
                    self.applet = False
            return done()
        if argv[0] == './chkbdinfo':
            flag, name = argv[1:]
            if name.endswith('-cvb.bin'):
                values = DECODE.get(self.cvb, {})
                if flag not in values:
                    return done(1, b'chkbdinfo: invalid EEPROM data\n')
                return done(0, values[flag].encode() + b'\n')
            return done(0, {'-i': self.cvm[0], '-k': self.cvm[1], '-f': 'fresh-fab', '-r': 'fresh-rev'}[flag].encode() + b'\n')
        raise AssertionError(argv)

    def power_cycle(self, identity):
        self.power_cycles = getattr(self, 'power_cycles', 0) + 1
        self.applet = False  # the operator power-cycles into boot ROM recovery

    def probe(self):
        if self.vendor.carrier_power_cycle is None:
            self.vendor.carrier_power_cycle = self.power_cycle
        def reenumerated(before):
            # Only a real power cycle produces a fresh boot ROM enumeration.
            if getattr(self, 'applet', False):
                raise ValueError('no fresh Force Recovery enumeration')
        with patch.object(self.vendor, 'single_rcm'), patch.object(self.vendor, 'usb_devnum', return_value='20'), \
                patch.object(self.vendor, 'await_reenumeration', side_effect=reenumerated):
            return self.vendor.probe()

    def tegraflash(self):
        return [c for c in self.calls if c[0] == '/usr/bin/python3']


class J40ProbeTests(ProbeBase):
    def test_accepted_outcomes_record_evidence(self):
        for mode, outcome in (('dump-failed', 'dump-failed'), ('blank-zero', 'blank-zero'), ('blank-ff', 'blank-ff'),
                              ('garbage', 'undecodable'), ('text-garbage', 'undecodable')):
            with self.subTest(mode):
                self.cvb = mode
                identity = self.probe()
                self.assertEqual(identity['carrier_evidence']['outcome'], outcome)
                self.assertEqual((identity['module'], identity['carrier'], identity['carrier_rule']),
                                 ('3767-0000', 'seeed-j401', carrier.RULE))
                self.assertNotEqual(identity['carrier'], '3768-0000')
                self.assertEqual(identity['fuses'].keys(), set(FUSE_NAMES))
                self.assertEqual(identity['ecid'], ECID)
                self.workspace.validate()

    def test_evidence_is_verbatim(self):
        self.cvb = 'blank-ff'
        identity = self.probe()
        record = identity['carrier_evidence']
        self.assertEqual((record['cvb_sha256'], record['cvb_size']), (hashlib.sha256(b'\xff'*256).hexdigest(), 256))
        self.assertEqual(identity['cvb_sha256'], record['cvb_sha256'])
        self.assertEqual(record['decoders'], {'-i': {'returncode': 1, 'output': 'chkbdinfo: invalid EEPROM data'},
                                              '-k': {'returncode': 1, 'output': 'chkbdinfo: invalid EEPROM data'}})
        self.cvb = 'text-garbage'
        record = self.probe()['carrier_evidence']
        self.assertEqual(record['decoded'], {'id': 'SEEED', 'sku': 'J401'})

    def test_failed_dump_is_recorded_exactly_and_keeps_authority(self):
        self.cvb, self.partial = 'dump-failed', True
        identity = self.probe()
        record = identity['carrier_evidence']
        self.assertEqual((record['outcome'], record['dump_returncode'], record['cvb_sha256'], record['cvb_size']),
                         ('dump-failed', 1, None, None))
        self.assertIsNone(identity['cvb_sha256'])
        self.assertIn('Could not read eeprom for module cvb', record['volatile']['dump_output_tail'])
        self.assertEqual(list((self.tree/'bootloader').glob('admiral-*-cvb.bin')), [])
        self.assertEqual(len(list((self.tree/'bootloader').glob('admiral-*-cvm.bin'))), 1)
        self.workspace.validate()
        self.probe()

    def test_module_and_fuse_reads_are_separate_from_the_tolerated_carrier_dump(self):
        self.cvb = 'dump-failed'
        self.probe()
        self.assertEqual(len(self.tegraflash()), 2)
        first, second = [c[c.index('--cmd')+1] for c in self.tegraflash()]
        # Module/fuse read first (ends with its own recovery reboot); the J401
        # carrier read last, whose failure leaves the MB2 applet running.
        self.assertTrue(first.startswith('readfuses') and 'dump eeprom cvm' in first and 'cvb' not in first)
        self.assertTrue(first.endswith('; reboot recovery'))
        self.assertRegex(second, r'^dump eeprom cvb admiral-[0-9a-f]{32}-cvb\.bin; reboot recovery$')
        self.assertEqual(self.power_cycles, 1)
        self.assertFalse(self.applet)

    def test_failed_carrier_read_without_power_cycle_stops(self):
        self.cvb = 'dump-failed'
        self.vendor.carrier_power_cycle = lambda identity: None   # operator did not power-cycle
        with self.assertRaisesRegex(ValueError, 'no fresh Force Recovery enumeration'):
            self.probe()

    def test_reenumeration_waits_for_a_new_device_number(self):
        sysfs = self.root/'sysfs'; (sysfs/'1-2').mkdir(parents=True)
        devnum = sysfs/'1-2'/'devnum'; devnum.write_text('20\n')
        ticks = []
        def sleep(seconds):
            ticks.append(seconds)
            if len(ticks) == 3:
                devnum.unlink()             # unit loses power
            if len(ticks) == 6:
                devnum.write_text('21\n')   # boot ROM enumerates again
        self.vendor.await_reenumeration('20', sysfs=sysfs, sleep=sleep)
        self.assertEqual(ticks[-1], 2)      # settle once, after the new number
        self.assertEqual(len(ticks), 7)
        devnum.write_text('21\n')
        with self.assertRaisesRegex(ValueError, 'no fresh Force Recovery enumeration'):
            self.vendor.await_reenumeration('21', sysfs=sysfs, timeout=1, sleep=lambda s: None)

    def test_failed_carrier_read_requires_a_power_cycle_callback(self):
        self.cvb = 'dump-failed'
        self.vendor.carrier_power_cycle = False
        with self.assertRaisesRegex(ValueError, 'power cycle required'):
            self.probe()

    def test_successful_carrier_read_needs_no_power_cycle(self):
        self.cvb = 'blank-ff'
        self.probe()
        self.assertEqual(getattr(self, 'power_cycles', 0), 0)

    def test_refused_outcomes_stop_the_probe(self):
        for mode in ('nvidia-3768', 'nvidia-3509', 'nvidia-3737', 'nvidia-4071', 'nvidia-other', 'sku-only', 'short'):
            with self.subTest(mode):
                self.cvb = mode
                with self.assertRaisesRegex(ValueError, 'recomputer-j40 carrier refused'):
                    self.probe()
                self.workspace.validate()

    def test_module_identity_is_exactly_as_strict_as_orin_nx(self):
        for cvm in (('3767', '0001'), ('3767', '0003'), ('3767', '0004'), ('3701', '0000'), ('3768', '0000')):
            with self.subTest(cvm):
                self.cvm = cvm
                with self.assertRaisesRegex(ValueError, 'allowlisted'):
                    self.probe()

    def test_security_fuses_still_fail_closed(self):
        original = self.edge
        def edge(argv, **kwargs):
            result = original(argv, **kwargs)
            if (self.tree/'bootloader/fuse_t234.bin').exists():
                (self.tree/'bootloader/fuse_t234.bin').write_text(''.join(n + (': 01\n' if n == 'OdmLock' else ': 00\n') for n in FUSE_NAMES))
            return result
        self.workspace.runner = edge
        with self.assertRaisesRegex(ValueError, 'programmed key/security'):
            self.probe()

    def test_board_must_remain_in_recovery_after_carrier_dump(self):
        self.cvb, self.swap_after = 'dump-failed', 1
        with self.assertRaisesRegex(ValueError, 'changed during carrier EEPROM read'):
            self.probe()

    def test_reprobe_compares_stable_fields_only(self):
        self.cvb = 'dump-failed'
        a, b = self.probe(), self.probe()
        self.assertNotEqual(a['carrier_evidence']['volatile'], b['carrier_evidence']['volatile'])
        self.assertEqual(carrier.stable(a), carrier.stable(b))
        self.cvb = 'blank-zero'
        self.assertNotEqual(carrier.stable(a), carrier.stable(self.probe()))

    def test_fresh_outputs_each_probe_and_no_cached_cvb(self):
        (self.tree/'bootloader/cvb.bin').write_bytes(b'\0'*256)
        self.workspace._seal_modes()
        self.workspace.expected = snapshot(self.tree, os.geteuid())
        self.cvb = 'dump-failed'
        self.assertEqual(self.probe()['carrier_evidence']['outcome'], 'dump-failed')
        self.assertFalse((self.tree/'bootloader/cvb.bin').exists())


class OrinNxUnchangedTests(ProbeBase):
    board = 'orin-nx'

    def test_single_invocation_and_exact_carrier(self):
        self.cvb = 'nvidia-3768'
        identity = self.probe()
        self.assertEqual((identity['module'], identity['carrier']), ('3767-0000', '3768-0000'))
        self.assertNotIn('carrier_evidence', identity)
        self.assertNotIn('carrier_rule', identity)
        self.assertEqual(len(self.tegraflash()), 1)
        sequence = self.tegraflash()[0][self.tegraflash()[0].index('--cmd')+1]
        self.assertIn('dump eeprom cvm', sequence)
        self.assertIn('dump eeprom cvb', sequence)
        self.assertFalse(carrier.requires_confirmation('orin-nx'))

    def test_every_non_3768_cvb_still_refused(self):
        for mode in ('nvidia-3737', 'nvidia-3509', 'nvidia-4071', 'nvidia-other'):
            with self.subTest(mode):
                self.cvb = mode
                with self.assertRaisesRegex(ValueError, 'allowlisted'):
                    self.probe()
                self.workspace.validate()

    def test_undecodable_or_failed_cvb_is_not_tolerated(self):
        self.cvb = 'blank-zero'
        with self.assertRaises(subprocess.CalledProcessError):
            self.probe()
        with self.assertRaisesRegex(ValueError, 'not prepared'):
            self.workspace.validate()

    def test_failed_dump_is_not_tolerated(self):
        self.cvb = 'dump-failed'
        with self.assertRaises(subprocess.CalledProcessError):
            self.probe()
        with self.assertRaisesRegex(ValueError, 'not prepared'):
            self.workspace.validate()


class ToleratedFailureTests(ProbeBase):
    NAME = 'admiral-' + '0'*32 + '-cvb.bin'

    def test_allowlist_is_only_the_cvb_dump_and_its_decode(self):
        yes = [['./chkbdinfo', '-i', self.NAME], ['./chkbdinfo', '-k', self.NAME],
               ['/usr/bin/python3', './tegraflash.py', '--chip', '0x23', '--cmd', 'dump eeprom cvb ' + self.NAME + '; reboot recovery', '--instance', '1-2']]
        no = [['./chkbdinfo', '-f', self.NAME], ['./chkbdinfo', '-i', 'cvm.bin'], ['./chkbdinfo', '-i', '../' + self.NAME],
              ['/usr/bin/python3', './tegraflash.py', '--cmd', 'dump eeprom cvm ' + self.NAME + '; reboot recovery'],
              ['/usr/bin/python3', './tegraflash.py', '--cmd', 'dump eeprom cvb ' + self.NAME + '; flash'],
              ['/usr/bin/python3', './tegraflash.py', '--cmd', 'rcmboot', '--cmd', 'dump eeprom cvb ' + self.NAME + '; reboot recovery'],
              ['/bin/false'], ['./flash.sh', '--read-info'],
              ['./flash.sh', '--read-info', '--usb-instance', '1-2', 'recomputer-j40-qspi', 'internal'],
              ['./flash.sh', '--no-flash', '--read-info', '--usb-instance', '1-2; rm', 'recomputer-j40-qspi', 'internal'],
              ['./flash.sh', '--no-flash', '--read-info', '--usb-instance', '1-2', 'recomputer-j40-qspi', 'internal', 'x']]
        yes.append(['./flash.sh', '--no-flash', '--read-info', '--usb-instance', '1-2', 'recomputer-j40-qspi', 'internal'])
        for argv in yes:
            self.assertTrue(tolerable_failure(argv), argv)
        for argv in no:
            self.assertFalse(tolerable_failure(argv), argv)

    def test_other_commands_still_end_authority_on_failure(self):
        self.workspace.runner = lambda argv, **kw: subprocess.CompletedProcess(argv, 3, b'boom')
        with self.assertRaisesRegex(ValueError, 'may not be tolerated'):
            self.workspace.run_tolerated(['/bin/false'])
        self.workspace.validate()
        with self.assertRaises(subprocess.CalledProcessError):
            self.workspace.run(['./chkbdinfo', '-i', self.NAME])
        with self.assertRaisesRegex(ValueError, 'not prepared'):
            self.workspace.validate()

    def test_tolerated_failure_returns_output_and_keeps_authority(self):
        self.workspace.runner = lambda argv, **kw: subprocess.CompletedProcess(argv, 3, b'boom')
        self.assertEqual(self.workspace.run_tolerated(['./chkbdinfo', '-i', self.NAME], cwd=self.tree/'bootloader'), (3, 'boom'))
        self.workspace.validate()
        self.assertIn('generated-tolerated-failure', (self.workspace.root/'preparation-manifest.json').read_text())

    def test_unlive_vendor_refuses_non_allowlisted_too(self):
        vendor = Vendor(self.tree, 'recomputer-j40', '1-2', runner=lambda *a, **k: None)
        with self.assertRaisesRegex(ValueError, 'may not be tolerated'):
            vendor.run_tolerated(['/bin/false'])


class VendorInputInstallTests(unittest.TestCase):
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive

    STOCK = ('/ {\n    misc {\n        eeprom {\n            cvm_eeprom_i2c_instance = <0>;\n'
             '            cvm_eeprom_read_size = <0x100>;\n            cvb_eeprom_i2c_slave_address = <0xac>;\n'
             '            cvb_eeprom_read_size = <0x100>;\n        };\n\n        fsi {\n        };\n    };\n};\n')

    def build(self, stock=None, release_changes=None, tree_changes=None, patch_text=None):
        stock = self.STOCK if stock is None else stock
        patched = stock.replace('cvb_eeprom_read_size = <0x100>', 'cvb_eeprom_read_size = <0>')
        target = vendor_inputs.MB2_TARGET
        diff = ''.join(difflib.unified_diff(stock.splitlines(True), patched.splitlines(True), 'a/' + target, 'b/' + target))
        bundle = self.root/'bundle'
        base = bundle/'vendor-inputs/recomputer-j40'
        for sub in ('patches', 'dtb', 'dtbo'):
            (base/sub).mkdir(parents=True, exist_ok=True)
        def pin(relative, data, install=None):
            (bundle/relative).write_bytes(data)
            record = {'path': relative, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if install:
                record['install'] = install
            return record
        prefix = 'vendor-inputs/recomputer-j40/'
        text = patch_text if patch_text is not None else 'Free text before the diff.\n\n' + diff
        record = {'source': {'repository': 'fixture'},
                  'mb2_patch': {'target': target, 'patch': pin(prefix + 'patches/0001.patch', text.encode()),
                                'stock_sha256': hashlib.sha256(stock.encode()).hexdigest(),
                                'patched_sha256': hashlib.sha256(patched.encode()).hexdigest()},
                  'config': pin(prefix + 'recomputer-j40-qspi.conf', b'# fixture conf\n', 'recomputer-j40-qspi.conf'),
                  'recovery_config': pin(prefix + 'recomputer-j40-recovery.conf', b'# fixture recovery conf\n',
                                         'recomputer-j40-recovery.conf'),
                  'sample_rootfs_members': pin(prefix + 'sample-rootfs-members.txt', b'etc\netc/release'),
                  'dtbs': [pin(prefix + 'dtb/' + Path(name).name, b'dtb-' + name.encode(), name) for name in vendor_inputs.DTB_INSTALL],
                  'dtbos': [pin(prefix + 'dtbo/' + Path(name).name, b'dtbo-' + name.encode(), name) for name in vendor_inputs.DTBO_INSTALL]}
        release = {'boards': {'recomputer-j40': {'vendor_inputs': record}, 'orin-nx': {}}}
        if release_changes:
            release_changes(release['boards']['recomputer-j40']['vendor_inputs'], bundle)
        files = {'Linux_for_Tegra/apply_binaries.sh': b'#!/bin/sh\n# -I lbzip2\n# -I lbzip2\nmkdir -p rootfs/usr/lib\n',
                 'Linux_for_Tegra/' + target: stock.encode()}
        for relative in vendor_inputs.REQUIRED_NVIDIA:
            files.setdefault('Linux_for_Tegra/' + relative, b'nvidia ' + relative.encode())
        if tree_changes:
            tree_changes(files)
        bsp, b = self.archive('bsp.tar', files)
        rootfs, r = self.archive('rootfs.tar', {'etc/release': b'pinned'})
        workspace = Workspace(self.root/'session', owner=os.geteuid())
        self.addCleanup(workspace.close)
        workspace.prepare(bsp, rootfs, {'archive': b, 'sample_rootfs': r})
        return workspace, release, bundle, stock, patched

    def test_install_applies_exact_patch_conf_dtbs_and_reseals(self):
        w, release, bundle, stock, patched = self.build()
        before = dict(w.expected)
        summary = vendor_inputs.install(w, release, 'recomputer-j40', bundle)
        tree = w.tree
        self.assertEqual((tree/vendor_inputs.MB2_TARGET).read_text(), patched)
        self.assertEqual((tree/'recomputer-j40-qspi.conf').read_bytes(), b'# fixture conf\n')
        for name in (*vendor_inputs.DTB_INSTALL, *vendor_inputs.DTBO_INSTALL):
            self.assertEqual((tree/name).read_bytes(), (b'dtbo-' if name.endswith('dtbo') else b'dtb-') + name.encode())
            self.assertEqual((tree/name).stat().st_mode & 0o777, 0o644)
        self.assertEqual(sum(1 for n in vendor_inputs.DTB_INSTALL if (tree/n).is_file()), 4)
        w.validate()
        self.assertEqual(set(w.expected) - set(before), {'recomputer-j40-qspi.conf', 'recomputer-j40-recovery.conf',
                                                         *vendor_inputs.DTB_INSTALL, *vendor_inputs.DTBO_INSTALL})
        self.assertEqual((tree/'recomputer-j40-recovery.conf').read_bytes(), b'# fixture recovery conf\n')
        manifest = json.loads((w.root/'preparation-manifest.json').read_text())
        self.assertEqual(manifest['stage'], 'vendor-inputs')
        self.assertEqual(manifest['inputs']['vendor_inputs'], summary)
        self.assertEqual(summary['mb2']['patched_sha256'], hashlib.sha256(patched.encode()).hexdigest())
        self.assertEqual(w.run([sys.executable, '-c', 'pass']), '')
        # the mutation is part of the held graph: any later edit is refused
        (tree/'recomputer-j40-qspi.conf').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'tree changed'):
            w.validate()

    def test_flow_helper_installs_only_for_boards_with_inputs(self):
        w, release, bundle, stock, patched = self.build()
        before = dict(w.expected)
        self.assertIsNone(flow.install_vendor_inputs(w, release, 'orin-nx'))
        self.assertIsNone(flow.install_vendor_inputs(w, release, 'orin'))
        self.assertIsNone(flow.install_vendor_inputs(w, release, 'thor'))
        self.assertEqual(w.expected, before)
        with patch('nvidia_flash_tools.vendor_inputs.install', return_value={'ok': 1}) as install:
            self.assertEqual(flow.install_vendor_inputs(w, release, 'recomputer-j40'), {'ok': 1})
        self.assertEqual(install.call_args[0][1:3], (release, 'recomputer-j40'))

    def test_unexpected_stock_mb2_is_refused_before_any_write(self):
        def tree_changes(files):
            files['Linux_for_Tegra/' + vendor_inputs.MB2_TARGET] = self.STOCK.replace('0xac', '0xad').encode()
        w, release, bundle, *_ = self.build(tree_changes=tree_changes)
        before = dict(w.expected)
        with self.assertRaisesRegex(ValueError, 'stock MB2 BCT sha256'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)
        self.assertEqual(w.expected, before)
        w.validate()
        self.assertFalse((w.tree/'recomputer-j40-qspi.conf').exists())

    def test_already_patched_tree_is_not_accepted(self):
        patched = self.STOCK.replace('cvb_eeprom_read_size = <0x100>', 'cvb_eeprom_read_size = <0>')
        def tree_changes(files):
            files['Linux_for_Tegra/' + vendor_inputs.MB2_TARGET] = patched.encode()
        w, release, bundle, *_ = self.build(tree_changes=tree_changes)
        with self.assertRaisesRegex(ValueError, 'stock MB2 BCT sha256'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)

    def test_patched_sha_gate(self):
        def change(record, bundle):
            record['mb2_patch']['patched_sha256'] = '0'*64
        w, release, bundle, *_ = self.build(release_changes=change)
        with self.assertRaisesRegex(ValueError, 'patched MB2 BCT sha256'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)
        self.assertEqual((w.tree/vendor_inputs.MB2_TARGET).read_text(), self.STOCK)
        self.assertFalse((w.tree/'recomputer-j40-qspi.conf').exists())

    def test_patch_that_does_not_apply_is_refused(self):
        other = self.STOCK.replace('0xac', '0xad')
        diff = ''.join(difflib.unified_diff(other.splitlines(True), other.replace('<0x100>;\n        };', '<0>;\n        };').splitlines(True),
                                            'a/' + vendor_inputs.MB2_TARGET, 'b/' + vendor_inputs.MB2_TARGET))
        w, release, bundle, *_ = self.build(patch_text=diff)
        with self.assertRaisesRegex(ValueError, 'context|removal'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)

    def test_input_pin_and_path_gates(self):
        def tamper(record, bundle):
            (bundle/record['config']['path']).write_bytes(b'# changed conf\n')
        w, release, bundle, *_ = self.build(release_changes=tamper)
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)
        cases = {'traversal': lambda r, b: r['config'].update(path='vendor-inputs/recomputer-j40/../x'),
                 'outside prefix': lambda r, b: r['config'].update(path='release.json'),
                 'wrong destination': lambda r, b: r['config'].update(install='kernel/dtb/recomputer-j40-qspi.conf'),
                 'dtb destination': lambda r, b: r['dtbs'][0].update(install='bootloader/evil.dtb'),
                 'missing dtb': lambda r, b: r['dtbs'].pop(),
                 'extra key': lambda r, b: r.update(extra={}),
                 'bad pin': lambda r, b: r['config'].update(sha256='z'*64),
                 'bad size': lambda r, b: r['config'].update(size=True)}
        for label, change in cases.items():
            with self.subTest(label):
                self.setUp(); self.addCleanup(self.tearDown)
                w, release, bundle, *_ = self.build(release_changes=change)
                with self.assertRaises(ValueError):
                    vendor_inputs.install(w, release, 'recomputer-j40', bundle)
                self.assertFalse((w.tree/'recomputer-j40-qspi.conf').exists())

    def test_symlinked_input_refused(self):
        def link(record, bundle):
            source = bundle/record['config']['path']
            real = source.with_name('real.conf')
            source.rename(real)
            source.symlink_to(real)
        w, release, bundle, *_ = self.build(release_changes=link)
        with self.assertRaises((ValueError, OSError)):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)

    def test_existing_destination_and_missing_nvidia_files_are_refused(self):
        w, release, bundle, *_ = self.build(tree_changes=lambda f: f.update({'Linux_for_Tegra/recomputer-j40-qspi.conf': b'lookalike'}))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)
        self.setUp(); self.addCleanup(self.tearDown)
        w, release, bundle, *_ = self.build(tree_changes=lambda f: f.pop('Linux_for_Tegra/p3767.conf.common'))
        with self.assertRaisesRegex(ValueError, 'pinned NVIDIA tree'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)

    def test_other_boards_cannot_smuggle_inputs_and_missing_record_is_refused(self):
        w, release, bundle, *_ = self.build()
        release['boards']['orin-nx'] = {'vendor_inputs': release['boards']['recomputer-j40']['vendor_inputs']}
        with self.assertRaisesRegex(ValueError, 'unexpected vendor inputs'):
            vendor_inputs.install(w, release, 'orin-nx', bundle)
        del release['boards']['recomputer-j40']['vendor_inputs']
        with self.assertRaisesRegex(ValueError, 'missing/unsupported'):
            vendor_inputs.install(w, release, 'recomputer-j40', bundle)

    def test_diff_applier_is_exact(self):
        target = vendor_inputs.MB2_TARGET
        original = 'a\nb\nc\nd\ne\n'
        good = ''.join(difflib.unified_diff(original.splitlines(True), 'a\nb\nX\nd\ne\n'.splitlines(True), 'a/' + target, 'b/' + target))
        self.assertEqual(vendor_inputs.apply_unified_diff(original, good, target), 'a\nb\nX\nd\ne\n')
        with self.assertRaisesRegex(ValueError, 'does not target'):
            vendor_inputs.apply_unified_diff(original, good, 'other/file')
        with self.assertRaisesRegex(ValueError, 'context|removal'):
            vendor_inputs.apply_unified_diff('a\nb\nQ\nd\ne\n', good, target)
        with self.assertRaisesRegex(ValueError, 'context|removal'):
            vendor_inputs.apply_unified_diff('z\n' + original, good, target)
        with self.assertRaisesRegex(ValueError, 'counts'):
            vendor_inputs.apply_unified_diff(original, good.replace('@@ -1,5 +1,5 @@', '@@ -1,5 +1,6 @@'), target)
        with self.assertRaisesRegex(ValueError, 'headers'):
            vendor_inputs.apply_unified_diff(original, 'no diff here\n', target)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            vendor_inputs.apply_unified_diff(original, good + 'garbage\n', target)


class FakeVendor:
    """Everything beneath vendor/hardware is replaced; flow.orin_session is real."""
    def __init__(self, events, identities):
        self.events, self.identities = events, list(identities)

    def probe(self):
        self.events.append('probe')
        return copy.deepcopy(self.identities.pop(0))

    def generate_qspi(self):
        self.events.append('generate')
        self.orin_plan = {'sha256': 'plan'}

    def ram_boot(self, identity):
        self.events.append('ram-boot')
        self.recovery_payload = {'boot_sha256': 'b'*64}

    def provision_qspi(self, package):
        self.events.append('provision')
        self.firmware_readback = {'sha256': 'f'*64, 'size': 67108864}

    def usb_devnum(self):
        return '7'

    def await_reenumeration(self, before):
        self.events.append('re-enumerated')


class FakeTransport:
    def shell(self, *args, **kwargs):
        if args[-1] == 'br_cid':
            return b'BR_CID: 0x0000000000000000000000123\n'
        raise AssertionError(args)

    def bind(self):
        pass


class SessionTests(unittest.TestCase):
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive
    workspace = test_execution.ExecutionTests.workspace
    DISK = {'path': '/dev/nvme0n1', 'serial': 'serial', 'model': 'model', 'capacity': 4096, 'sector': 512,
            'major': 259, 'minor': 0, 'device': '/devices/nvme'}

    def identity(self, board='recomputer-j40', data=b'\0'*256, **changes):
        record = carrier.evidence(dump_returncode=0, dump_output='', data=data, sha256=hashlib.sha256(data).hexdigest(),
                                  size=len(data), decoders={'-i': (1, 'invalid'), '-k': (1, 'invalid')})
        identity = {'br_cid': ECID, 'ecid': ECID, 'module': '3767-0000', 'fab': 'f', 'revision': 'r',
                    'cvm_sha256': 'c'*64, 'cvb_sha256': record['cvb_sha256'], 'fuses': {'OdmLock': '00'}}
        if board == 'recomputer-j40':
            identity.update(carrier=carrier.CARRIER, carrier_rule=carrier.RULE, carrier_evidence=record)
        else:
            identity.update(carrier='3768-0000')
        identity.update(changes)
        return identity

    def run_session(self, board='recomputer-j40', identities=None, confirmation='default', erase_answer=''):
        w = self.workspace()
        (w.tree/'bootloader').mkdir()
        (w.tree/'bootloader/boot0.img').write_bytes(b'device-generation-edge')
        w._seal_modes()
        w.expected = snapshot(w.tree, os.geteuid())
        helper = self.root/'helper'
        helper.write_bytes(b'authenticated-helper-edge')
        release = {'recovery': {'helper': {'sha256': sha256(helper), 'size': helper.stat().st_size,
                                           'source_sha256': sha256(ROOT/'recovery-io.c')}},
                   'boards': {board: {'image': {'sha256': 'i'*64}}}}
        args = argparse.Namespace(board=board, usb_port='1-2', helper=helper, image=self.root/'image', journal=self.root/'journal',
                                  experimental_first_test=True, security_observation=lambda i: 'secure-boot-disabled-observed')
        self.asked = []
        if confirmation == 'default':
            confirmation = carrier.CONFIRMATION
        if confirmation is not None:
            def ask(identity):
                self.asked.append(copy.deepcopy(identity))
                return confirmation
            args.carrier_confirmation = ask
        self.events, self.contracts = [], []
        base = self.identity(board)
        vendor = FakeVendor(self.events, identities or [base, base])
        def confirm(stage, contract, pin):
            self.events.append('approve-' + stage)
            self.contracts.append((stage, copy.deepcopy(contract), pin))
            return pin if stage == 'firmware' else erase_answer
        with patch('nvidia_flash_tools.orin_recovery.transport', side_effect=lambda v, i: FakeTransport()):
            return flow.orin_session(w, args, release, confirm=confirm, select_disk=lambda t: dict(self.DISK),
                                     vendor_factory=lambda *a, **k: vendor, request_recovery=lambda i: self.events.append('recovery'))

    def test_confirmed_run_reaches_both_approvals_with_evidence_and_phrase_bound(self):
        with self.assertRaisesRegex(ValueError, 'NVMe approval declined'):
            self.run_session()
        self.assertEqual(self.events, ['probe', 'generate', 'ram-boot', 'approve-firmware', 'provision', 'recovery',
                                       're-enumerated', 'probe', 'ram-boot', 'approve-erase-nvme'])
        self.assertEqual([stage for stage, *_ in self.contracts], ['firmware', 'erase-nvme'])
        self.assertEqual(len(self.asked), 1)
        self.assertNotIn('carrier_confirmation', self.asked[0])
        for stage, contract, pin in self.contracts:
            board = contract['physical_board']
            self.assertEqual(board['carrier_confirmation'], carrier.CONFIRMATION)
            self.assertEqual(board['carrier_rule'], carrier.RULE)
            self.assertEqual(board['carrier_evidence']['outcome'], 'blank-zero')
            self.assertEqual(board['carrier_evidence']['cvb_sha256'], hashlib.sha256(b'\0'*256).hexdigest())
            self.assertEqual(board['uefi_policy'], 'secure-boot-disabled-observed')
            self.assertEqual(board['module'], '3767-0000')
            self.assertEqual(pin, hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_digest_changes_with_cvb_evidence_and_with_confirmation(self):
        pins = {}
        for label, data in (('zero', b'\0'*256), ('ff', b'\xff'*256)):
            self.setUp(); self.addCleanup(self.tearDown)
            ident = self.identity(data=data)
            with self.assertRaisesRegex(ValueError, 'declined'):
                self.run_session(identities=[ident, ident])
            pins[label] = [pin for *_, pin in self.contracts]
        self.assertNotEqual(pins['zero'][0], pins['ff'][0])
        self.assertNotEqual(pins['zero'][1], pins['ff'][1])
        # the typed phrase is itself an approval input
        self.setUp(); self.addCleanup(self.tearDown)
        w = self.workspace()
        helper = self.root/'h'; helper.write_bytes(b'h')
        board = carrier.bind_confirmation(self.identity(), carrier.CONFIRMATION)
        kwargs = dict(workspace=w, release={}, installer=ROOT, helper=helper, recovery=helper, package={}, disk=dict(self.DISK))
        _, with_phrase = flow.approval_contract(board=board, **kwargs)
        changed = dict(board, carrier_confirmation=carrier.CONFIRMATION)
        self.assertEqual(flow.approval_contract(board=changed, **kwargs)[1], with_phrase)
        for broken in (dict(board, carrier_confirmation='x'), {k: v for k, v in board.items() if k != 'carrier_confirmation'}):
            with self.assertRaisesRegex(ValueError, 'confirmation'):
                flow.approval_contract(board=broken, **kwargs)
        refused = copy.deepcopy(board)
        refused['carrier_evidence'] = carrier.evidence(dump_returncode=0, dump_output='', data=b'x'*256, sha256='a'*64,
                                                      size=256, decoders={'-i': (0, '3768'), '-k': (0, '0000')})
        with self.assertRaisesRegex(ValueError, 'refused'):
            flow.approval_contract(board=refused, **kwargs)

    def test_missing_wrong_or_replayed_confirmation_stops_before_ram_boot(self):
        for confirmation in (None, 'yes', 'OBSERVED SECURE BOOT DISABLED', ''):
            with self.subTest(confirmation):
                self.setUp(); self.addCleanup(self.tearDown)
                with self.assertRaisesRegex(ValueError, 'confirmation'):
                    self.run_session(confirmation=confirmation)
                self.assertEqual(self.events, ['probe'])
                self.assertEqual(self.contracts, [])

    def test_refused_cvb_evidence_in_identity_cannot_be_confirmed(self):
        refused = self.identity()
        refused['carrier_evidence'] = carrier.evidence(dump_returncode=0, dump_output='', data=b'x'*256, sha256='a'*64,
                                                       size=256, decoders={'-i': (0, '3768'), '-k': (0, '0000')})
        with self.assertRaisesRegex(ValueError, 'carrier refused'):
            self.run_session(identities=[refused, refused])
        self.assertEqual(self.events, ['probe'])

    def test_board_swapped_cvb_between_probes_is_refused(self):
        first = self.identity()
        second = self.identity(data=b'\xff'*256)
        with self.assertRaisesRegex(ValueError, 'changed after firmware stage'):
            self.run_session(identities=[first, second])
        self.assertIn('provision', self.events)
        self.assertNotIn('approve-erase-nvme', self.events)

    def test_orin_nx_needs_no_confirmation_and_is_unchanged(self):
        with self.assertRaisesRegex(ValueError, 'NVMe approval declined'):
            self.run_session(board='orin-nx', confirmation=None)
        self.assertEqual(self.asked, [])
        for _, contract, _ in self.contracts:
            self.assertEqual(contract['physical_board']['carrier'], '3768-0000')
            self.assertNotIn('carrier_evidence', contract['physical_board'])
            self.assertNotIn('carrier_confirmation', contract['physical_board'])

    def test_j40_identity_cannot_reach_approval_through_the_nx_identity_shape(self):
        # a 3768-0000 identity on the recomputer-j40 board has no carrier evidence
        with self.assertRaises(ValueError):
            self.run_session(identities=[self.identity(board='orin-nx'), self.identity(board='orin-nx')])
        self.assertEqual(self.contracts, [])

    def test_guided_prompt(self):
        identity = self.identity()
        with patch('builtins.input', return_value=carrier.CONFIRMATION) as ask, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(thor.carrier_confirmation(identity), carrier.CONFIRMATION)
        self.assertIn('blank-zero', out.getvalue())
        self.assertIn(identity['carrier_evidence']['cvb_sha256'], out.getvalue())
        self.assertIn(carrier.CONFIRMATION, ask.call_args[0][0])
        for answer in ('', 'yes', carrier.CONFIRMATION.lower()):
            with patch('builtins.input', return_value=answer), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'declined'):
                    thor.carrier_confirmation(identity)

    def test_thor_main_install_namespace_carries_the_callback(self):
        captured = {}
        def guided(ns, release):
            captured['ns'] = ns
            raise RuntimeError('stop after namespace')
        release = {'boards': {'recomputer-j40': {'image': {'name': 'x'}}}}
        with patch('nvidia_flash_tools.thor.bundle', return_value=release), patch('nvidia_flash_tools.thor.prerequisites', return_value=[]), \
                patch('nvidia_flash_tools.thor.os.geteuid', return_value=0), patch('nvidia_flash_tools.security.trusted_directory', side_effect=lambda *a, **k: os.open('/', os.O_RDONLY)), \
                patch('nvidia_flash_tools.download.guided', side_effect=guided), contextlib.redirect_stdout(io.StringIO()), \
                patch('builtins.input', side_effect=['I ACCEPT THE RISKS', '/opt/x/session', '/opt/x/downloads']):
            with self.assertRaisesRegex(RuntimeError, 'stop after namespace'):
                thor.main(['install', '--board', 'recomputer-j40', '--bundle-pin', 'a'*64])
        self.assertIs(captured['ns'].carrier_confirmation, thor.carrier_confirmation)
        self.assertEqual(captured['ns'].board, 'recomputer-j40')


class DocsTests(unittest.TestCase):
    def test_readme_section_and_notice(self):
        readme = (ROOT/'README.md').read_text()
        self.assertIn('## 2C. Install on reComputer J40/J4012', readme)
        self.assertIn('Not tested on physical devices', readme)
        section = readme[readme.index('## 2C.'):readme.index('## 3.')]
        for text in ('FC REC', '0955:7323', 'recomputer-j40', carrier.CONFIRMATION, 'wiki.seeedstudio.com/reComputer_J4012_Flash_Jetpack'):
            self.assertIn(text, section)
        self.assertIn(carrier.CONFIRMATION, readme[readme.index('## 3.'):])


if __name__ == '__main__':
    unittest.main()
