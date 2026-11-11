#!/usr/bin/env python3
"""Refresh the mic-733-ao vendor-input size/SHA256 pins in release.json from the files.

Developer tool (not packaged). Pins only bytes that exist in vendor-inputs/mic-733-ao/;
NVIDIA stock/patched hashes are constants verified against a real R39.2.1 tree by
tests/test_orin_mic733.py (NVIDIA_VENDOR_ROOT).
"""
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
P = 'vendor-inputs/mic-733-ao/'
def pin(rel, install=None):
    data = (ROOT/rel).read_bytes()
    record = {'path': rel, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    if install:
        record['install'] = install
    return record
release = json.loads((ROOT/'release.json').read_text())
board = release['boards']['mic-733-ao']
v = board['vendor_inputs']
v['config'] = pin(P + 'mic-733-ao-qspi.conf', 'mic-733-ao-qspi.conf')
v['recovery_config'] = pin(P + 'mic-733-ao-recovery.conf', 'mic-733-ao-recovery.conf')
v['sample_rootfs_members'] = pin(P + 'sample-rootfs-members.txt')
v['mb2_bct'] = pin(P + 'bct/tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts',
                   'bootloader/generic/BCT/tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts')
v['mb1_patch']['patch'] = pin(P + 'patches/0001-mb1-pinmux-gpio-mic-733-ao.patch')
v['dtbs'] = [pin(P + 'dtb/tegra234-mic-733-ao+p3701-' + s + '.dtb', 'kernel/dtb/tegra234-mic-733-ao+p3701-' + s + '.dtb')
             for s in ('0000', '0004', '0005')]
(ROOT/'release.json').write_text(json.dumps(release, indent=2) + '\n')
print('pinned', len(v['dtbs']) + 5, 'mic-733-ao vendor inputs')
