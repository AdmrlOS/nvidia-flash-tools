#!/usr/bin/env python3
"""Guided Jetson installer. Not tested on physical devices."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

from nvidia_flash_tools import flow
from nvidia_flash_tools.image import sha256
from nvidia_flash_tools.install import authenticate, check_artifact, prerequisites

ROOT = Path(__file__).resolve().parent.parent


def bundle(root, pin):
    """Independent manifest pin is the trust root, never a self-computed pin."""
    root = Path(root)
    if not re.fullmatch('[0-9a-f]{64}', pin or '') or sha256(root/'engineering-manifest.json') != pin:
        raise ValueError('independently supplied engineering bundle SHA256 required')
    manifest = json.loads((root/'engineering-manifest.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('authorization') is not None or manifest.get('hardware_qualified') is not False:
        raise ValueError('unsupported engineering bundle classification')
    for name, record in manifest['artifacts'].items():
        if (not isinstance(name, str) or not name or '\\' in name or
                Path(name).is_absolute() or any(part in ('', '.', '..') for part in name.split('/'))):
            raise ValueError('invalid bundle artifact path')
        artifact = root / name
        if any(path.is_symlink() for path in (artifact, *artifact.parents) if path != root and root in path.parents):
            raise ValueError('bundle artifact symlink refused')
        check_artifact(artifact, record)
    check_artifact(root/'recovery-io', manifest['recovery']['helper'])
    release = root/'engineering-release.json'
    return authenticate(release, manifest['engineering_release_sha256'])


def verify_image(path, release, board='thor'):
    check_artifact(path, release['boards'][board]['image'])
    from nvidia_flash_tools.fingerprint import admiral_image
    admiral_image(path)
    print('Admiral image: full SHA256, both GPTs and partition fingerprint verified.')


def recovery_port(sysfs=Path('/sys/bus/usb/devices')):
    candidates = [p for p in sysfs.iterdir() if (p/'idVendor').is_file()
                  and (p/'idVendor').read_text().strip() == '0955']
    if len(candidates) != 1:
        raise ValueError('connect exactly one NVIDIA recovery endpoint; disconnect other NVIDIA USB devices')
    device = candidates[0]
    if not re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*', device.name) or not re.fullmatch('[0-9a-f]{4}', (device/'idProduct').read_text().strip()):
        raise ValueError('unverified recovery endpoint topology/product')
    # This selects only a candidate, not Thor identity. Vendor.probe must verify
    # chip, fresh EEPROM module/carrier/SKU and security before any approval.
    print('NVIDIA USB candidate on physical port ' + device.name + '; exact module/carrier identity still requires authenticated vendor probe.')
    return device.name


def approval(stage, contract, pin):
    print(json.dumps({'stage': stage, 'exact_approval': contract, 'audit_sha256': pin}, indent=2))
    phrase = 'ERASE NVME' if stage == 'erase-nvme' else 'ERASE FIRMWARE AND NVME EXPERIMENTAL'
    print('Not tested on physical devices. Power loss may require stock NVIDIA recovery. Firmware stage authorizes board firmware replacement and the subsequent separately confirmed complete NVMe erase.')
    print('WARNING: this stage irreversibly replaces ' + ('the displayed NVMe disk.' if stage == 'erase-nvme' else 'board firmware.'))
    # Preserve the backend exact digest contract without asking users to retype
    # hashes. Never reuse consent for another stage/identity/generated package.
    return pin if input('Type ' + phrase + ' to authorize this exact stage: ').strip() == phrase else ''


def security_observation(identity):
    print('Current board ECID: ' + identity['ecid'])
    print('Before entering recovery, observe UEFI Secure Boot DISABLED on THIS board (UEFI menu or Ubuntu mokutil --sb-state). Fuses are separately read and checked automatically. Unknown/enabled is unsupported. Never change security or enroll keys to proceed.')
    answer = input('Type OBSERVED SECURE BOOT DISABLED only if you personally observed it on this board immediately before this session: ').strip()
    if answer != 'OBSERVED SECURE BOOT DISABLED':
        raise ValueError('unknown/incompatible Secure Boot status; stop before persistent writes')
    return 'secure-boot-disabled-observed'


def carrier_confirmation(identity):
    """Identity-stage prompt for boards whose carrier has no NVIDIA-format EEPROM."""
    from nvidia_flash_tools import carrier
    print(carrier.describe(identity))
    print('The Seeed J401 carrier has no NVIDIA carrier EEPROM, so the carrier cannot be proven from EEPROM data. '
          'The cvb result above is recorded in, and bound to, the destructive approval.')
    answer = input('Type ' + carrier.CONFIRMATION + ' only if the unit in front of you is a Seeed reComputer J40/J4012 '
                   'with its original J401 carrier and you observed its labels: ').strip()
    if answer != carrier.CONFIRMATION:
        raise ValueError('explicit carrier confirmation declined; no carrier assumed, stop before persistent writes')
    return answer


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('check', 'prepare', 'install'), default='install')
    parser.add_argument('--bundle-pin', help='independent operator-provided engineering-manifest SHA256; otherwise prompted')
    parser.add_argument('--board', choices=('thor','orin','orin-nx','recomputer-j40'), default='thor')
    args = parser.parse_args(argv)
    board = args.board
    print(board.upper() + ': Not tested on physical devices. Test-key images; exact reference kit only.')
    consent = False
    if args.action == 'install':
        print('Risk: failure to boot, power-loss recovery, irreversible firmware replacement AND complete NVMe data loss. Back up everything. No production readiness claimed.')
        consent = input('Type I ACCEPT THE RISKS to continue: ').strip() == 'I ACCEPT THE RISKS'
        if not consent:
            raise ValueError('risk consent declined; no downloads/device writes')
    pin = args.bundle_pin or input('Paste the independently received bundle SHA256: ').strip()
    release = bundle(ROOT, pin)
    issues = prerequisites()
    print('Native Ubuntu PC prerequisite report (no package installation performed):')
    print('\n'.join(issues) if issues else 'Ubuntu 22.04/24.04/26.04 physical x86_64 host prerequisites present.')
    if args.action == 'check':
        verify_image(Path(input('Admiral image file: ').strip()).expanduser(), release, board)
        print('Offline check complete; hardware remains unverified.')
        return 0
    if issues:
        raise ValueError('resolve the reported host prerequisites; review/approve and run the printed apt command yourself, then retry')
    if os.geteuid() != 0:
        raise ValueError('Preparation/execution requires explicit root escalation. Place the authenticated bundle under a root-owned non-writable parent, then run sudo /usr/bin/python3 /trusted/path/thor.py ' + args.action + ' --bundle-pin ' + pin + '. No password is read or stored by this installer.')
    # Workspace enforces trusted root ownership. No implicit sudo or apt action.
    from nvidia_flash_tools.security import trusted_directory
    fd = trusted_directory(ROOT); os.close(fd)
    fd = trusted_directory(ROOT/'nvidia_flash_tools'); os.close(fd)
    destination = Path(input('New private preparation/session directory under a trusted root-owned parent: ').strip()).absolute()
    downloads = Path(input('Verified download cache under a trusted root-owned parent: ').strip()).absolute()
    ns = SimpleNamespace(board=board, output=destination, download_dir=downloads,
                         accept_nvidia_license=False, nvidia_archive=None, sample_rootfs=None,
                         helper=ROOT/'recovery-io', journal=destination/'install-journal.json',
                         guided_approval=approval, experimental_first_test=consent,
                         security_observation=security_observation,
                         carrier_confirmation=carrier_confirmation)
    from nvidia_flash_tools.download import guided
    guided(ns, release)
    if args.action == 'prepare':
        flow.prepare(ns, release)
        print('Offline preparation complete. No selected-board generation or hardware qualification implied.')
        return 0
    # No public image URL exists in this release. Do not invent an auto-download.
    ns.image = Path(input('Operator-supplied Admiral image file (no authenticated public URL available): ').strip()).expanduser()
    verify_image(ns.image, release, board)
    observed = security_observation({'ecid':'not yet probed; observe the ONE board you will connect'})
    ns.security_observation = lambda identity: observed
    input('Connect that ONE selected reference kit in Force Recovery, then press Enter: ')
    ns.usb_port = recovery_port()
    try:
        result = flow.install(ns, release, issues)
    except BaseException as exc:
        report = {'schema':1, 'classification':'experimental-first-test', 'status':'stopped', 'error_type':type(exc).__name__, 'identifiers':'redacted', 'auto_upload':False}
        if destination.is_dir():
            _report(destination, report)
        raise
    _report(destination, {'schema':1,'classification':'experimental-first-test','status':'write-verified-not-boot-qualified','identifiers':'redacted','auto_upload':False})
    return 0


def _report(destination, report):
    # New exclusive nofollow file; never overwrite caller-controlled names.
    fd = os.open(destination/'first-test-report.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)



if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, EOFError, subprocess.SubprocessError) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
