"""Advantech MIC-733-AO (mic-733-ao): selector, carrier rule, vendor inputs, approval.

Offline only. No MIC-733 carrier EEPROM result has been captured: the cvb
fixtures below are synthetic stand-ins for the *classes* of outcome in
carrier.CVB_TABLE and make no claim about what the real carrier returns. All
board identifiers (BR_CID/ECID, NVMe serial) are synthetic.
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
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nvidia_flash_tools import carrier, flow, orin, orin_firmware, thor, vendor_inputs
from nvidia_flash_tools.image import sha256
from nvidia_flash_tools.vendor import ALIASES, BOARDS, RECOVERY_ALIASES, Vendor
from nvidia_flash_tools.workspace import Workspace, snapshot
from tests import test_execution
from tests.test_orin_j40 import ECID, MB2_LOG, ProbeBase, FakeVendor, FakeTransport

ROOT = Path(__file__).resolve().parent.parent
RELEASE = json.loads((ROOT/'release.json').read_text())
BOARD = 'mic-733-ao'
PHRASE = 'OBSERVED ADVANTECH MIC-733-AO CARRIER'


def record(data, rc=0, decoded=None, output='', board=BOARD):
    decoders = {flag: (0, value) if value is not None else (1, 'chkbdinfo: invalid')
                for flag, value in (decoded or {}).items()}
    digest = hashlib.sha256(data).hexdigest() if isinstance(data, bytes) else None
    size = len(data) if isinstance(data, bytes) else None
    return carrier.evidence(dump_returncode=rc, dump_output=output, data=data, sha256=digest,
                            size=size, decoders=decoders, board=board)


class SelectorTests(unittest.TestCase):
    def test_board_table_alias_and_existing_boards_unchanged(self):
        self.assertEqual(BOARDS[BOARD][:2], ('3701', '0005'))
        self.assertEqual(BOARDS[BOARD][4], '23')
        self.assertFalse(BOARDS[BOARD][2].isdigit())       # never equal to a chkbdinfo decode
        self.assertEqual(ALIASES[BOARD], 'mic-733-ao-qspi')
        self.assertEqual(RECOVERY_ALIASES[BOARD], 'mic-733-ao-recovery')
        vendor = Vendor(ROOT, BOARD, '1-2', runner=lambda: None)
        self.assertEqual((vendor.alias, vendor.recovery_alias), ('mic-733-ao-qspi', 'mic-733-ao-recovery'))
        self.assertEqual(BOARDS['orin'], ('3701', '0000', '3737', '0000', '23'))
        self.assertEqual(BOARDS['recomputer-j40'], ('3767', '0000', 'seeed', 'j401', '23'))
        self.assertEqual(Vendor(ROOT, 'orin', '1-2', runner=lambda: None).alias, 'jetson-agx-orin-devkit')

    def test_entrypoints_parse_board(self):
        with patch('nvidia_flash_tools.thor.main', return_value=0) as main:
            self.assertEqual(orin.main(['prepare', '--board', BOARD]), 0)
        main.assert_called_once_with(['prepare', '--board', BOARD])
        for bad in ('mic-733', 'mic-733-ao5a1', 'MIC-733-AO'):
            with patch('nvidia_flash_tools.thor.main') as main, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    orin.main(['check', '--board', bad])
            main.assert_not_called()
        from nvidia_flash_tools import install
        with patch.object(sys, 'argv', ['install.py', 'check', '--board', BOARD, '--manifest-sha256', '0'*64]):
            with self.assertRaisesRegex(ValueError, 'differs'):
                install.main()
        with patch('nvidia_flash_tools.thor.bundle', return_value={'boards': {BOARD: {'image': {}}}}), \
                patch('builtins.input', return_value='/x'), patch('nvidia_flash_tools.thor.prerequisites', return_value=[]), \
                patch('nvidia_flash_tools.thor.verify_image') as verify, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(thor.main(['check', '--board', BOARD, '--bundle-pin', 'a'*64]), 0)
        self.assertEqual(verify.call_args[0][2], BOARD)

    def test_release_record_and_image_pin(self):
        rec = RELEASE['boards'][BOARD]
        self.assertEqual((rec['module'], rec['carrier'], rec['carrier_rule'], rec['vendor_board']),
                         ('3701-0005', carrier.MIC733_CARRIER, carrier.MIC733_RULE, 'mic-733-ao-qspi'))
        self.assertIsNone(rec['download_url'])
        self.assertEqual(rec['image']['name'], 'admiral-nvidia-tegra234-advantech-mic-733-ao-staging.img')
        self.assertIsInstance(rec['image']['size'], int)
        self.assertRegex(rec['image']['sha256'], '^[0-9a-f]{64}$')
        self.assertNotIn('pin_status', rec['image'])
        self.assertIs(RELEASE['hardware_qualified'], False)

    def test_unpinned_image_record_is_refused_before_reading_the_file(self):
        from nvidia_flash_tools.install import check_artifact
        unpinned = {'boards': {BOARD: {'image': {'name': 'admiral-nvidia-tegra234-advantech-mic-733-ao-staging.img',
                                                 'size': None, 'sha256': None}}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'admiral-nvidia-tegra234-advantech-mic-733-ao-staging.img'
            path.write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'no size/SHA256 pinned'):
                check_artifact(path, unpinned['boards'][BOARD]['image'])
            with self.assertRaisesRegex(ValueError, 'no size/SHA256 pinned'):
                thor.verify_image(path, unpinned, BOARD)
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                check_artifact(path, {'name': path.name, 'size': 1, 'sha256': '0'*64})


class VendorPinTests(unittest.TestCase):
    def test_repo_inputs_match_pins_and_are_packaged(self):
        inputs = vendor_inputs.load(RELEASE, BOARD, ROOT)
        self.assertEqual([name for name, _ in inputs['dtbs']], list(vendor_inputs.MIC733_DTB_INSTALL))
        self.assertEqual(set(inputs['mb1']['sections']), {t for _, t in vendor_inputs.MIC733_MB1_FILES})
        self.assertIn(b'cvb_eeprom_read_size = <0x0>;', inputs['mb2_bct'])
        self.assertIn(b'gbe-uphy-config-0,hsstp-lane-map-3,nvhs-uphy-config-0,hsio-uphy-config-16', inputs['config'])
        self.assertIn(b'MB2_BCT="tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts"', inputs['config'])
        self.assertIn(b'source "${LDK_DIR}/mic-733-ao-qspi.conf"', inputs['recovery_config'])
        self.assertIn(b'NO_RECOVERY_IMG=0', inputs['recovery_config'])
        # BSP flash-qspi.sh NVIDIA_SHA values, byte for byte.
        self.assertEqual(inputs['nvidia_sha256']['bootloader/tegra234-mb2-bct-common.dtsi'],
                         '42572d28b0dec865e9e0db3a6c04c03e77dd1c06fce80d76f45c3a12f2ed096b')
        self.assertEqual(inputs['nvidia_sha256']['p3737-0000-p3701-0000.conf'],
                         'f29bd15a7de039eda68bc3955d8d002189fb4929ae9f8ace9d396960c39e9e45')
        self.assertEqual([f['patched_sha256'] for f in inputs['mb1']['files']],
                         ['f1c3310a5982b332521c86719f8a88dd0260f321a6d85e5d5b4d1be9dd00c1a2',
                          'a6314888f78778cff13ca4c6a9d85d79cc27736a0289755ac2ab8dda53a29adb'])
        import package
        rec = RELEASE['boards'][BOARD]['vendor_inputs']
        pinned = [rec['config'], rec['recovery_config'], rec['sample_rootfs_members'], rec['mb2_bct'],
                  rec['mb1_patch']['patch'], *rec['dtbs']]
        self.assertTrue({item['path'] for item in pinned} <= set(package.FILES))
        self.assertIn('vendor-inputs/mic-733-ao/README.md', package.FILES)
        self.assertIn('tests/test_orin_mic733.py', package.FILES)
        self.assertNotIn('scripts/pin-mic733-inputs.py', package.FILES)

    def test_pinned_dtbs_are_the_three_sku_build_outputs(self):
        # Hashes equal the mic-733-ao kernel build's generic-dtbs outputs.
        rec = RELEASE['boards'][BOARD]['vendor_inputs']['dtbs']
        self.assertEqual([(Path(r['install']).name, r['size'], r['sha256']) for r in rec], [
            ('tegra234-mic-733-ao+p3701-0000.dtb', 220401, '2dcba6e853e345f0695db03d87661b3cff9b45a02da0de63c5f0d5f097ef0992'),
            ('tegra234-mic-733-ao+p3701-0004.dtb', 220389, 'caef145ff801a53b0baff68c0b0f8c8cccf7dc7edb9380a20c6d3ff1e308100e'),
            ('tegra234-mic-733-ao+p3701-0005.dtb', 220401, '04459652db9f00517a068ab3d8490952103e8d9725e25f604ef3406217d43065')])
        for item in rec:
            self.assertTrue(b'on Advantech MIC-733-AO' in (ROOT/item['path']).read_bytes(), item['path'])

    def test_one_flipped_byte_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            import shutil
            bundle = Path(tmp)/'bundle'
            shutil.copytree(ROOT/'vendor-inputs', bundle/'vendor-inputs')
            vendor_inputs.load(RELEASE, BOARD, bundle)
            for key in ('mb2_bct', 'config'):
                target = bundle/RELEASE['boards'][BOARD]['vendor_inputs'][key]['path']
                original = target.read_bytes()
                target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, 'SHA256'):
                    vendor_inputs.load(RELEASE, BOARD, bundle)
                target.write_bytes(original)

    def test_inputs_outside_the_board_prefix_are_refused(self):
        release = copy.deepcopy(RELEASE)
        release['boards'][BOARD]['vendor_inputs']['config'] = dict(
            RELEASE['boards']['recomputer-j40']['vendor_inputs']['config'])
        with self.assertRaisesRegex(ValueError, 'path'):
            vendor_inputs.load(release, BOARD, ROOT)

    def test_real_mb1_patch_and_nvidia_pins_against_real_tree_when_available(self):
        if not vendor_path('p3701.conf.common').is_file():
            self.skipTest('pinned NVIDIA vendor tree not available')
        inputs = vendor_inputs.load(RELEASE, BOARD, ROOT)
        for relative, expected in inputs['nvidia_sha256'].items():
            self.assertEqual(sha256(vendor_path(relative)), expected, relative)
        for item in inputs['mb1']['files']:
            stock = vendor_path(item['source'])
            self.assertEqual(sha256(stock), item['stock_sha256'])
            patched = vendor_inputs.apply_unified_diff(stock.read_text(), inputs['mb1']['sections'][item['target']],
                                                       item['target'])
            self.assertEqual(hashlib.sha256(patched.encode()).hexdigest(), item['patched_sha256'])
        for relative in vendor_inputs.MIC733_REQUIRED_NVIDIA:
            self.assertTrue(vendor_path(relative).is_file(), relative)

    def test_split_unified_diff(self):
        a = ''.join(difflib.unified_diff(['x\n', '-- y\n', 'z\n'], ['x\n', 'Y\n', 'z\n'], 'a/one', 'b/one'))
        b = ''.join(difflib.unified_diff(['1\n', '2\n'], ['1\n', '3\n'], 'a/two', 'b/two'))
        sections = vendor_inputs.split_unified_diff('Header text.\n\n' + a + b)
        self.assertEqual(sections, {'one': a, 'two': b})
        self.assertEqual(vendor_inputs.apply_unified_diff('x\n-- y\nz\n', sections['one'], 'one'), 'x\nY\nz\n')
        for broken in (a + a, a.replace('+++ b/one', '+++ b/other'), a[:-3], 'no headers\n',
                       a.replace('@@ -1,3 +1,3 @@', '@@ -1,4 +1,3 @@')):
            with self.assertRaises(ValueError):
                vendor_inputs.split_unified_diff(broken)


class CarrierRuleTests(unittest.TestCase):
    def test_rule_constants_and_captured_table(self):
        rule = carrier.rule_for(BOARD)
        self.assertEqual((rule['carrier'], rule['rule'], rule['confirmation']),
                         ('advantech-mic-733', 'mic-733-ao-cvb-v2', PHRASE))
        self.assertTrue(carrier.requires_confirmation(BOARD))
        # Tightened from the first real RAM-only probe: only MB2's dump-failed answer.
        self.assertEqual(carrier.accepted(BOARD), {'dump-failed'})
        self.assertTrue(carrier.accepted(BOARD) <= carrier.OUTCOMES)
        self.assertEqual(carrier.MIC733_PINNED_CVB_SHA256, frozenset())
        self.assertTrue({'3737', '3711', '3740'} <= set(carrier.MIC733_NVIDIA_CARRIER_IDS))
        self.assertIsInstance(carrier.MIC733_CVB_TIMEOUT, int)
        self.assertLessEqual(carrier.MIC733_CVB_TIMEOUT, 600)
        for text in (PHRASE, 'mic-733-ao-cvb-v2', 'SW_REC1', 'SW_RST1'):
            self.assertIn(text, (ROOT/'docs/reference.md').read_text())

    def test_accepted_and_refused_outcomes(self):
        accepted = {'dump-failed': record(None, rc=1, output=MB2_LOG)}
        for outcome, rec in accepted.items():
            with self.subTest(outcome):
                self.assertEqual((rec['outcome'], rec['rule']), (outcome, carrier.MIC733_RULE))
                self.assertIs(carrier.check_evidence(rec, BOARD), rec)
        refused = [record(None, rc=1, output='Error: Return value 8\n'),          # dump-error
                   record(None, rc=0),                                            # no file, rc 0
                   record(b'\0'*255), record(False),                             # unexpected-size
                   # Accepted by provisional v1, refused since the real capture (v2).
                   record(b'\0'*256, decoded={'-i': None, '-k': None}),           # blank-zero
                   record(b'\xff'*256, decoded={'-i': None, '-k': None}),         # blank-ff
                   record(bytes(range(256)), decoded={'-i': 'ADV', '-k': None})]   # undecodable
        for ident in ('3737', '3711', '3740', '3701', '1234'):
            refused.append(record(bytes(range(256)), decoded={'-i': ident, '-k': '0000'}))
            refused.append(record(bytes(range(256)), decoded={'-i': None, '-k': ident}))
        for rec in refused:
            with self.subTest(rec['outcome'], reason=rec['reason']):
                with self.assertRaisesRegex(ValueError, 'mic-733-ao carrier refused'):
                    carrier.check_evidence(rec, BOARD)
        self.assertIn('3737', record(bytes(range(256)), decoded={'-i': '3737', '-k': '0000'})['reason'])

    def test_rules_never_cross(self):
        j40 = record(None, rc=1, output=MB2_LOG, board='recomputer-j40')
        mic = record(None, rc=1, output=MB2_LOG)
        self.assertEqual(j40['rule'], carrier.RULE)
        with self.assertRaisesRegex(ValueError, 'missing/unknown mic-733-ao carrier evidence'):
            carrier.check_evidence(j40, BOARD)
        with self.assertRaisesRegex(ValueError, 'missing/unknown recomputer-j40 carrier evidence'):
            carrier.check_evidence(mic, 'recomputer-j40')
        identity = {'module': '3701-0005', 'carrier': carrier.MIC733_CARRIER, 'carrier_rule': carrier.MIC733_RULE,
                    'carrier_evidence': mic}
        with self.assertRaisesRegex(ValueError, 'confirmation'):
            carrier.bind_confirmation(dict(identity), carrier.CONFIRMATION, BOARD)    # J401 phrase
        with self.assertRaisesRegex(ValueError, 'recomputer-j40 carrier evidence'):
            carrier.bind_confirmation(dict(identity), PHRASE, 'recomputer-j40')
        bound = carrier.bind_confirmation(copy.deepcopy(identity), PHRASE, BOARD)
        carrier.validate_bound(bound)
        for broken in (dict(bound, carrier_confirmation=carrier.CONFIRMATION),
                       dict(bound, carrier_evidence=j40), dict(bound, carrier_rule=carrier.RULE),
                       {k: v for k, v in bound.items() if k != 'carrier_confirmation'}):
            with self.assertRaises(ValueError):
                carrier.validate_bound(broken)
        with self.assertRaisesRegex(ValueError, 'unknown carrier rule'):
            carrier.validate_bound({'carrier': 'x', 'carrier_rule': 'made-up'})
        carrier.validate_bound({'carrier': '3737-0000', 'module': '3701-0000'})       # NVIDIA boards untouched

    def test_tightening_hooks_apply_to_this_board_only(self):
        rec = record(bytes(range(256)))
        with patch.object(carrier, 'MIC733_PINNED_CVB_SHA256', frozenset({'a'*64})), \
                patch.object(carrier, 'MIC733_ACCEPTED', frozenset({'dump-failed', 'undecodable'})):
            with self.assertRaisesRegex(ValueError, 'not a pinned MIC-733-AO capture'):
                carrier.check_evidence(rec, BOARD)
            carrier.check_evidence(record(bytes(range(256)), board='recomputer-j40'), 'recomputer-j40')
        with patch.object(carrier, 'MIC733_ACCEPTED', frozenset({'dump-failed'})):
            with self.assertRaisesRegex(ValueError, 'refused: cvb outcome blank-zero'):
                carrier.check_evidence(record(b'\0'*256), BOARD)
            carrier.check_evidence(record(None, rc=1, output=MB2_LOG), BOARD)
            carrier.check_evidence(record(b'\0'*256, board='recomputer-j40'), 'recomputer-j40')


class MicProbeTests(ProbeBase):
    """Real Vendor.probe and fresh_eeproms with only the tool runner replaced."""
    board = BOARD

    def setUp(self):
        super().setUp()
        self.cvm = ('3701', '0005')
        self.timeouts = []

    def edge(self, argv, **kwargs):
        if argv[0] == '/usr/bin/python3':
            self.timeouts.append((argv[argv.index('--cmd')+1], kwargs.get('timeout')))
            if getattr(self, 'hang', False) and 'cvb' in argv[argv.index('--cmd')+1]:
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))
        return super().edge(argv, **kwargs)

    def test_accepted_outcomes_record_mic733_evidence(self):
        for mode, outcome in (('dump-failed', 'dump-failed'),):
            with self.subTest(mode):
                self.cvb, self.vendor.carrier_record = mode, None
                identity = self.probe()
                self.assertEqual((identity['module'], identity['carrier'], identity['carrier_rule']),
                                 ('3701-0005', 'advantech-mic-733', 'mic-733-ao-cvb-v2'))
                self.assertEqual(identity['carrier_evidence']['outcome'], outcome)
                self.assertEqual(identity['carrier_evidence']['rule'], carrier.MIC733_RULE)
                self.assertEqual(identity['ecid'], ECID)
                self.workspace.validate()

    def test_module_must_be_exactly_p3701_0005(self):
        for cvm in (('3701', '0000'), ('3701', '0004'), ('3701', '0008'), ('3767', '0000'), ('3737', '0000')):
            with self.subTest(cvm):
                self.cvm, self.vendor.carrier_record = cvm, None
                with self.assertRaisesRegex(ValueError, 'allowlisted'):
                    self.probe()

    def test_refused_carrier_outcomes_stop_the_probe(self):
        for mode in ('nvidia-3737', 'nvidia-3768', 'nvidia-other', 'sku-only', 'short',
                     'blank-zero', 'blank-ff', 'garbage'):
            with self.subTest(mode):
                self.cvb, self.vendor.carrier_record = mode, None
                with self.assertRaisesRegex(ValueError, 'mic-733-ao carrier refused'):
                    self.probe()
                self.workspace.validate()

    def test_reads_order_timeout_and_recovery_prompt(self):
        self.cvb = 'dump-failed'
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.probe()
        first, second = self.timeouts
        self.assertTrue(first[0].startswith('readfuses') and 'cvb' not in first[0])
        self.assertNotEqual(first[1], carrier.MIC733_CVB_TIMEOUT)
        self.assertRegex(second[0], r'^dump eeprom cvb admiral-[0-9a-f]{32}-cvb\.bin; reboot recovery$')
        self.assertEqual(second[1], carrier.MIC733_CVB_TIMEOUT)
        self.assertEqual(self.power_cycles, 1)
        text = out.getvalue()
        for word in ('SW_REC1', 'SW_RST1', 'MIC-733-AO'):
            self.assertIn(word, text)
        self.assertNotIn('jumper', text)

    def test_hanging_carrier_dump_stops_with_a_bounded_error(self):
        self.cvb, self.hang = 'dump-failed', True
        with self.assertRaisesRegex(ValueError, r'did not return within 180 s.*SW_REC1'):
            self.probe()

    def test_no_reenumeration_names_the_buttons(self):
        sysfs = self.root/'sysfs'; (sysfs/'1-2').mkdir(parents=True)
        (sysfs/'1-2'/'devnum').write_text('20\n')
        with self.assertRaisesRegex(ValueError, 'SW_REC1.*SW_RST1'):
            self.vendor.await_reenumeration('20', sysfs=sysfs, timeout=1, sleep=lambda s: None)
        j40 = Vendor(self.tree, 'recomputer-j40', '1-2', workspace=self.workspace)
        with self.assertRaisesRegex(ValueError, 'jumper fitted'):
            j40.await_reenumeration('20', sysfs=sysfs, timeout=1, sleep=lambda s: None)

    def test_later_probe_reuses_record_and_rereads_module(self):
        self.cvb = 'dump-failed'
        first = self.probe()
        again = self.probe()
        self.assertEqual((self.power_cycles, len(self.tegraflash())), (1, 3))
        self.assertEqual(carrier.stable(again), carrier.stable(first))


class GeometryTests(unittest.TestCase):
    def test_measured_before_approval_only_for_unmeasured_boards(self):
        self.assertEqual(orin_firmware.MEASURE_BEFORE_APPROVAL, ('mic-733-ao',))
        class T:
            def __init__(self, values): self.values, self.calls = values, []
            def shell(self, *args, **kwargs):
                self.calls.append(args)
                return (self.values[Path(args[1]).name] + '\n').encode()
        good = {'name': 'spi0.0', 'type': 'nor', 'size': '67108864', 'erasesize': '65536', 'writesize': '1'}
        t = T(good)
        self.assertEqual(orin_firmware.qspi_geometry(t), good)
        self.assertTrue(all(c[0] == '/bin/cat' and c[1].startswith('/sys/class/mtd/mtd0/') for c in t.calls))
        for name, value in (('size', '33554432'), ('erasesize', '262144'), ('type', 'nand')):
            with self.assertRaisesRegex(ValueError, name + '=' + value):
                orin_firmware.qspi_geometry(T(dict(good, **{name: value})))


class SessionTests(unittest.TestCase):
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive
    workspace = test_execution.ExecutionTests.workspace
    DISK = {'path': '/dev/nvme0n1', 'serial': 'SYNTHETIC0001', 'model': 'model', 'capacity': 4096, 'sector': 512,
            'major': 259, 'minor': 0, 'device': '/devices/nvme'}
    GEOMETRY = {'name': 'spi0.0', 'type': 'nor', 'size': '67108864', 'erasesize': '65536', 'writesize': '1'}

    def identity(self):
        # The captured outcome of the real MIC-733-AO6A1: MB2's dump-failed answer.
        rec = record(None, rc=1, output=MB2_LOG)
        return {'br_cid': ECID, 'ecid': ECID, 'module': '3701-0005', 'fab': 'f', 'revision': 'r',
                'cvm_sha256': 'c'*64, 'cvb_sha256': rec['cvb_sha256'], 'fuses': {'OdmLock': '00'},
                'carrier': carrier.MIC733_CARRIER, 'carrier_rule': carrier.MIC733_RULE, 'carrier_evidence': rec}

    def run_session(self, confirmation=PHRASE, geometry=None, identities=None):
        w = self.workspace()
        (w.tree/'bootloader').mkdir()
        (w.tree/'bootloader/boot0.img').write_bytes(b'device-generation-edge')
        w._seal_modes()
        w.expected = snapshot(w.tree, os.geteuid())
        helper = self.root/'helper'
        helper.write_bytes(b'authenticated-helper-edge')
        release = {'recovery': {'helper': {'sha256': sha256(helper), 'size': helper.stat().st_size,
                                           'source_sha256': sha256(ROOT/'recovery-io.c')}},
                   'boards': {BOARD: {'image': {'sha256': 'i'*64}}}}
        args = argparse.Namespace(board=BOARD, usb_port='1-2', helper=helper, image=self.root/'image',
                                  journal=self.root/'journal', experimental_first_test=True,
                                  security_observation=lambda i: 'secure-boot-disabled-observed',
                                  carrier_confirmation=lambda identity: confirmation)
        self.events, self.contracts = [], []
        base = self.identity()
        vendor = FakeVendor(self.events, identities or [base, base])
        values = dict(self.GEOMETRY, **(geometry or {}))
        class Transport(FakeTransport):
            def shell(inner, *a, **k):
                if a and a[0] == '/bin/cat' and a[1].startswith('/sys/class/mtd/mtd0/'):
                    self.events.append('mtd-' + Path(a[1]).name)
                    return (values[Path(a[1]).name] + '\n').encode()
                return FakeTransport.shell(inner, *a, **k)
        def confirm(stage, contract, pin):
            self.events.append('approve-' + stage)
            self.contracts.append((stage, copy.deepcopy(contract), pin))
            return pin if stage == 'firmware' else ''
        with patch('nvidia_flash_tools.orin_recovery.transport', side_effect=lambda v, i: Transport()), \
                contextlib.redirect_stdout(io.StringIO()) as self.out:
            return flow.orin_session(w, args, release, confirm=confirm, select_disk=lambda t: dict(self.DISK),
                                     vendor_factory=lambda *a, **k: vendor,
                                     request_recovery=lambda i: self.events.append('recovery'))

    def test_phrase_evidence_and_geometry_are_bound_into_both_approvals(self):
        with self.assertRaisesRegex(ValueError, 'NVMe approval declined'):
            self.run_session()
        first = self.events.index('approve-firmware')
        self.assertTrue(all(self.events.index('mtd-' + n) < first for n in orin_firmware.GEOMETRY_FIELDS))
        self.assertIn('QSPI mtd0 measured in RAM recovery', self.out.getvalue())
        for stage, contract, pin in self.contracts:
            board = contract['physical_board']
            self.assertEqual((board['carrier'], board['carrier_rule'], board['carrier_confirmation']),
                             (carrier.MIC733_CARRIER, carrier.MIC733_RULE, PHRASE))
            self.assertEqual(board['module'], '3701-0005')
            self.assertEqual(contract['firmware_package']['qspi_geometry'], self.GEOMETRY)
            self.assertEqual(pin, hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_unacceptable_geometry_stops_before_the_firmware_approval(self):
        with self.assertRaisesRegex(ValueError, 'erasesize=262144'):
            self.run_session(geometry={'erasesize': '262144'})
        self.assertNotIn('approve-firmware', self.events)
        self.assertNotIn('provision', self.events)

    def test_wrong_or_j401_phrase_stops_before_generation(self):
        for typed in ('', 'yes', carrier.CONFIRMATION, PHRASE.lower(), PHRASE + ' '):
            with self.subTest(typed=typed):
                self.setUp(); self.addCleanup(self.tearDown)
                with self.assertRaisesRegex(ValueError, 'confirmation'):
                    self.run_session(confirmation=typed)
                self.assertEqual(self.events, ['probe'])

    def test_guided_prompt_names_the_mic733(self):
        identity = self.identity()
        with patch('builtins.input', return_value=PHRASE) as ask, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(thor.carrier_confirmation(identity), PHRASE)
        self.assertIn('Advantech MIC-733 carrier has no NVIDIA carrier EEPROM', out.getvalue())
        self.assertIn(PHRASE, ask.call_args[0][0])
        self.assertIn('MIC-733-AO', ask.call_args[0][0])
        self.assertNotIn('Seeed', ask.call_args[0][0] + out.getvalue())
        with patch('builtins.input', return_value=carrier.CONFIRMATION), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'declined'):
                thor.carrier_confirmation(identity)


class InstallTests(unittest.TestCase):
    """vendor_inputs.install against a synthetic tree carrying the pinned stock bytes."""
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive
    GPIO = '#include "tegra234-gpio.h"\n\n/ {\n\tgpio@2200000 {\n\t\tgpio-input = <\n\t\t\tTEGRA234_MAIN_GPIO(Z, 1)\n\t\t\t>;\n\t};\n};\n'
    PINMUX = '/dts-v1/;\n#include "pinctrl-tegra.h"\n\n#include "tegra234-mb1-bct-gpio-p3701-0000-a04.dtsi"\n/ {\n};\n'

    def build(self, mutate=None):
        gpio_src, gpio_dst = vendor_inputs.MIC733_MB1_FILES[0]
        pin_src, pin_dst = vendor_inputs.MIC733_MB1_FILES[1]
        gpio_new = self.GPIO.replace('(Z, 1)', '(Z, 2)')
        pin_new = self.PINMUX.replace('a04.dtsi', 'a04-mic-733-ao.dtsi')
        diff = ''.join(difflib.unified_diff(self.GPIO.splitlines(True), gpio_new.splitlines(True), 'a/' + gpio_dst, 'b/' + gpio_dst))
        diff += ''.join(difflib.unified_diff(self.PINMUX.splitlines(True), pin_new.splitlines(True), 'a/' + pin_dst, 'b/' + pin_dst))
        bundle = self.root/'bundle'
        prefix = vendor_inputs.MIC733_PREFIX
        def pin(relative, data, install=None):
            (bundle/relative).parent.mkdir(parents=True, exist_ok=True)
            (bundle/relative).write_bytes(data)
            item = {'path': relative, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if install:
                item['install'] = install
            return item
        nvidia = {name: b'nvidia ' + name.encode() for name in vendor_inputs.MIC733_NVIDIA_PINNED}
        rec = {'source': {'repository': 'fixture'},
               'config': pin(prefix + 'mic-733-ao-qspi.conf', b'# conf\n', vendor_inputs.MIC733_CONF_INSTALL),
               'recovery_config': pin(prefix + 'mic-733-ao-recovery.conf', b'# rec\n', vendor_inputs.MIC733_RECOVERY_CONF_INSTALL),
               'sample_rootfs_members': pin(prefix + 'sample-rootfs-members.txt', b'etc\netc/release'),
               'mb2_bct': pin(prefix + 'bct/mb2.dts', b'/ { mb2-misc { }; };\n', vendor_inputs.MIC733_MB2_INSTALL),
               'mb1_patch': {'patch': pin(prefix + 'patches/0001.patch', ('Header.\n\n' + diff).encode()),
                             'files': [{'source': gpio_src, 'target': gpio_dst,
                                        'stock_sha256': hashlib.sha256(self.GPIO.encode()).hexdigest(),
                                        'patched_sha256': hashlib.sha256(gpio_new.encode()).hexdigest()},
                                       {'source': pin_src, 'target': pin_dst,
                                        'stock_sha256': hashlib.sha256(self.PINMUX.encode()).hexdigest(),
                                        'patched_sha256': hashlib.sha256(pin_new.encode()).hexdigest()}]},
               'nvidia_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in nvidia.items()},
               'dtbs': [pin(prefix + 'dtb/' + Path(n).name, b'dtb ' + n.encode(), n) for n in vendor_inputs.MIC733_DTB_INSTALL]}
        release = {'boards': {BOARD: {'vendor_inputs': rec}}}
        files = {'Linux_for_Tegra/apply_binaries.sh': b'#!/bin/sh\n# -I lbzip2\n# -I lbzip2\nmkdir -p rootfs/usr/lib\n',
                 'Linux_for_Tegra/' + gpio_src: self.GPIO.encode(), 'Linux_for_Tegra/' + pin_src: self.PINMUX.encode(),
                 'Linux_for_Tegra/kernel/dtb/existing.dtb': b'nvidia dtb'}
        files.update({'Linux_for_Tegra/' + n: d for n, d in nvidia.items()})
        for relative in vendor_inputs.MIC733_REQUIRED_NVIDIA:
            files.setdefault('Linux_for_Tegra/' + relative, b'nvidia ' + relative.encode())
        if mutate:
            mutate(files, rec, bundle)
        bsp, b = self.archive('bsp.tar', files)
        rootfs, r = self.archive('rootfs.tar', {'etc/release': b'pinned'})
        w = Workspace(self.root/'session', owner=os.geteuid())
        self.addCleanup(w.close)
        w.prepare(bsp, rootfs, {'archive': b, 'sample_rootfs': r})
        return w, release, bundle, gpio_new, pin_new

    def test_install_creates_copies_and_leaves_nvidia_files_untouched(self):
        w, release, bundle, gpio_new, pin_new = self.build()
        before = dict(w.expected)
        summary = vendor_inputs.install(w, release, BOARD, bundle)
        tree = w.tree
        (gpio_src, gpio_dst), (pin_src, pin_dst) = vendor_inputs.MIC733_MB1_FILES
        self.assertEqual((tree/gpio_dst).read_text(), gpio_new)
        self.assertEqual((tree/pin_dst).read_text(), pin_new)
        self.assertEqual((tree/gpio_src).read_text(), self.GPIO)         # NVIDIA's own file unchanged
        self.assertEqual((tree/pin_src).read_text(), self.PINMUX)
        added = set(w.expected) - set(before)
        self.assertEqual(added, {vendor_inputs.MIC733_CONF_INSTALL, vendor_inputs.MIC733_RECOVERY_CONF_INSTALL,
                                 vendor_inputs.MIC733_MB2_INSTALL, gpio_dst, pin_dst, *vendor_inputs.MIC733_DTB_INSTALL})
        self.assertEqual({k: v for k, v in w.expected.items() if k in before}, before)
        self.assertEqual(summary['board'], BOARD)
        w.validate()
        (tree/vendor_inputs.MIC733_MB2_INSTALL).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'tree changed'):
            w.validate()

    def test_modified_nvidia_file_or_stock_mb1_is_refused_before_any_write(self):
        cases = {
            'nvidia pin': lambda f, r, b: f.update({'Linux_for_Tegra/p3701.conf.common': b'other'}),
            'mb2 common already patched': lambda f, r, b: f.update({'Linux_for_Tegra/bootloader/tegra234-mb2-bct-common.dtsi': b'j40'}),
            'stock mb1': lambda f, r, b: f.update({'Linux_for_Tegra/' + vendor_inputs.MIC733_MB1_FILES[0][0]: b'x'}),
            'patched pin': lambda f, r, b: r['mb1_patch']['files'][1].update(patched_sha256='0'*64),
            'missing required': lambda f, r, b: f.pop('Linux_for_Tegra/bootloader/generic/tegra234-bpmp-3701-0005-3737-0000.dtb'),
            'existing destination': lambda f, r, b: f.update({'Linux_for_Tegra/mic-733-ao-qspi.conf': b'lookalike'}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.setUp(); self.addCleanup(self.tearDown)
                w, release, bundle, *_ = self.build(mutate)
                before = dict(w.expected)
                with self.assertRaises(ValueError):
                    vendor_inputs.install(w, release, BOARD, bundle)
                self.assertEqual(w.expected, before)
                w.validate()
                self.assertFalse((w.tree/vendor_inputs.MIC733_MB2_INSTALL).exists())

    def test_record_shape_gates(self):
        cases = {'extra key': lambda r: r.update(extra=1),
                 'mb1 target swapped': lambda r: r['mb1_patch']['files'].reverse(),
                 'mb1 file missing': lambda r: r['mb1_patch']['files'].pop(),
                 'dtb missing': lambda r: r['dtbs'].pop(),
                 'dtb destination': lambda r: r['dtbs'][0].update(install='bootloader/x.dtb'),
                 'nvidia pin set': lambda r: r['nvidia_sha256'].pop('p3701.conf.common'),
                 'mb2 destination': lambda r: r['mb2_bct'].update(install='bootloader/tegra234-mb2-bct-common.dtsi')}
        for label, change in cases.items():
            with self.subTest(label):
                self.setUp(); self.addCleanup(self.tearDown)
                w, release, bundle, *_ = self.build()
                change(release['boards'][BOARD]['vendor_inputs'])
                with self.assertRaises(ValueError):
                    vendor_inputs.install(w, release, BOARD, bundle)

    def test_j40_and_other_boards_unaffected(self):
        w, release, bundle, *_ = self.build()
        release['boards']['orin'] = {'vendor_inputs': release['boards'][BOARD]['vendor_inputs']}
        with self.assertRaisesRegex(ValueError, 'unexpected vendor inputs'):
            vendor_inputs.install(w, release, 'orin', bundle)
        self.assertIsNone(flow.install_vendor_inputs(w, {'boards': {'orin': {}}}, 'orin'))


class DocsTests(unittest.TestCase):
    def test_readme_section(self):
        readme = (ROOT/'README.md').read_text()
        self.assertIn('## 2D. Install on Advantech MIC-733-AO', readme)
        section = readme[readme.index('## 2D.'):readme.index('## 3.')]
        for text in ('0955:7023', 'SW_REC1', 'SW_RST1', '--board mic-733-ao', PHRASE, 'P3701-0005'):
            self.assertIn(text, section)
        self.assertNotIn('jumper', section.lower())
        self.assertIn(PHRASE, readme[readme.index('## 3.'):])
        self.assertIn('mic-733-ao', (ROOT/'docs/troubleshooting.md').read_text())


if __name__ == '__main__':
    unittest.main()
