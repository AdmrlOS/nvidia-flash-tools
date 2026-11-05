"""Pinned R39.2.1 vendor boundaries and fail-closed evidence parsing.

Source contracts: flash.sh readfuses text, chkbdinfo -i/-k/-f/-r, and
tegraflash_impl_t{234,264}.py writing '<fuse>: <lowercase hex>\n'.
No hardware output fixture has been captured: fixtures are source-derived.
"""
import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET

from nvidia_flash_tools.image import sha256

# board -> (module, sku, carrier, carrier_sku, chip). recomputer-j40 has no
# NVIDIA carrier ID: its carrier fields are not matched against any EEPROM
# decode; nvidia_flash_tools.carrier owns that rule.
BOARDS = {'thor': ('3834', '0008', '4071', '0000', '26'),
          'orin': ('3701', '0000', '3737', '0000', '23'),
          'orin-nx': ('3767', '0000', '3768', '0000', '23'),
          'recomputer-j40': ('3767', '0000', 'seeed', 'j401', '23')}
# NVIDIA flash.sh board configuration per board; anything absent is jetson-agx-<board>-devkit.
ALIASES = {'orin-nx': 'jetson-orin-nano-devkit-super',
           'recomputer-j40': 'recomputer-j40-qspi'}
# Boards whose flash configuration disables recovery.img (every *-qspi.conf)
# build the RAM-boot recovery image with a pinned recovery variant.
RECOVERY_ALIASES = {'recomputer-j40': 'recomputer-j40-recovery'}


def clean_env():
    # Whitelist rather than forgetting one of NVIDIA's many environment overrides.
    from nvidia_flash_tools.security import ENV
    return dict(ENV)


def fuse_info(text, board):
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9]*): ([0-9a-f]+)', line)
        if not match or match[1] in values or len(match[2]) % 2:
            raise ValueError('unsupported/duplicate NVIDIA readfuses format')
        values[match[1]] = match[2]
    required = {'PublicKeyHash', 'BootSecurityInfo', 'SecurityMode', 'ArmJtagDisable',
                'DebugAuthentication', 'SwReserved', 'OdmLock'}
    required |= {'PkcPubkeyHash1', 'PkcPubkeyHash2'} if board != 'thor' else {'OptInEnable'}
    if not required <= values.keys():
        raise ValueError('missing security fuse information')
    # Conservative engineering policy: reject any programmed security/debug/lock
    # word. ProductionMode itself is not used as a proxy for authentication.
    if any(int(values[name], 16) for name in required):
        raise ValueError('programmed key/security/recovery policy not supported')
    return values


def bootrom_uid(text, board):
    # flash.sh extracts the second space-separated field on the BR_CID line.
    # Refuse timestamps/unknown wrappers rather than invent a flexible UID decoder.
    # Exact optional debug prefix is present in the shipped tegrarcm_v2 binary
    # format strings: '[%d] %s(): BR_CID: 0x%.8x%.8x%.8x%.8x'.
    matches = re.findall(r'^(?:\[[0-9]+\] [A-Za-z_][A-Za-z0-9_]*\(\): )?BR_CID: (0x[0-9a-fA-F]{32})$', text, re.M)
    if len(matches) != 1:
        raise ValueError('unsupported NVIDIA BR_CID output; capture required')
    uid = matches[0]
    chip = BOARDS[board][4]
    if uid[6:8].lower() != chip:
        raise ValueError('wrong recovery chip')
    mode = (int(uid[2], 16) & (14 if board == 'thor' else 8), int(uid[3:5], 16) & 240)
    if mode != (8, 0):
        raise ValueError('unknown/secured/non-production recovery device')
    # Unified GetTargetECID slices raw 'BR_CID: 0x...' at 17, dropping
    # seven metadata hex digits and keeping 25 manufacturing-ID digits.
    return {'br_cid': uid, 'ecid': '0x' + uid[9:] if board == 'thor' else uid}


def qspi_package(xml, index=None):
    raw = Path(xml).read_bytes()
    if len(raw) > 4 * 1024 * 1024 or b'<!DOCTYPE' in raw or b'<!ENTITY' in raw:
        raise ValueError('unsupported XML declarations/size')
    # Only authenticated private vendor package XML; DTD/entities refused above.
    tree = ET.ElementTree(ET.fromstring(raw))
    devices = tree.findall('.//device')
    if len(devices) != 1 or devices[0].attrib != {
            'type': 'spi', 'instance': '0', 'sector_size': '512', 'num_sectors': '131072'}:
        raise ValueError('vendor package is not exactly one stock 64MiB SPI target')
    parts = devices[0].findall('partition')
    if not parts or any(p.get('name') in ('APP', 'UDA', 'esp', 'efi') for p in parts):
        raise ValueError('invalid QSPI partition target allowlist')
    if index:
        rows = list(csv.reader(Path(index).read_text().splitlines(), skipinitialspace=True))
        if not rows or any(len(row) < 8 or not re.fullmatch(r'3:0:[A-Za-z0-9_-]+', row[1]) for row in rows):
            raise ValueError('non-SPI/unknown vendor flash.idx target')
    return [p.get('name') for p in parts]


def verify_vendor_tree(archive, tree):
    """Reject copied provenance stamps/lookalike scripts before executing code."""
    with tarfile.open(archive) as source:
        for member in source:
            parts = Path(member.name).parts
            if not parts or parts[0] != 'Linux_for_Tegra':
                continue
            relative = Path(*parts[1:])
            if not relative.parts or relative.parts[0] == 'rootfs':
                continue
            target = tree / relative
            if member.issym():
                if not target.is_symlink() or os.readlink(target) != member.linkname:
                    raise ValueError('vendor archive symlink differs: ' + str(relative))
            elif member.isfile():
                if target.is_symlink() or not target.is_file() or target.stat().st_size != member.size:
                    raise ValueError('vendor archive member differs: ' + str(relative))
                with source.extractfile(member) as stream:
                    from nvidia_flash_tools.image import digest
                    if digest(stream, member.size) != sha256(target):
                        raise ValueError('vendor archive member hash differs: ' + str(relative))


def extract_private(archive, destination, record):
    if archive.stat().st_size != record['size'] or sha256(archive) != record['sha256']:
        raise ValueError('NVIDIA archive authentication failed')
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        # Trusted pinned vendor archives contain symlinks; fully_trusted is not
        # appropriate. Python's data filter permits contained relative links.
        source.extractall(destination, filter='data')


class Vendor:
    def __init__(self, tree, board, port, runner=None, workspace=None):
        if board not in BOARDS or not re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*', port):
            raise ValueError('unsupported board/physical USB port')
        self.tree, self.board, self.port = Path(tree).resolve(), board, port
        self.alias = ALIASES.get(board) or 'jetson-agx-' + board + '-devkit'
        self.recovery_alias = RECOVERY_ALIASES.get(board, self.alias)
        # J401: called after a failed carrier EEPROM read to have the operator
        # power-cycle the unit back into boot ROM recovery.
        self.carrier_power_cycle = None
        self.cvb_dump = None
        # Signed SPI graph that plan() approved; generate_qspi snapshots it live.
        self.qspi_signed = self.tree / 'bootloader/signed'
        self.live = runner is None
        self.workspace = workspace
        if workspace is not None and workspace.tree != self.tree:
            raise ValueError("workspace/tree mismatch")
        self.runner = runner or subprocess.run
        self.audit = self.tree.parent / 'vendor-audit.jsonl'

    def run(self, argv, env=None, cwd=None, timeout=1800):
        if self.live:
            if self.workspace is None:
                raise ValueError('fresh authenticated locked workspace required')
            return self.workspace.run(argv, env, cwd, timeout)
        environment = clean_env()
        environment.update(env or {})
        result = self.runner([str(x) for x in argv], cwd=cwd or self.tree,
                             env=environment, timeout=timeout, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=False)
        raw = result.stdout
        with self.audit.open('a') as log:
            log.write(json.dumps({'argv': list(map(str, argv)), 'environment': environment,
                                  'returncode': result.returncode, 'output': raw.decode(errors='replace')}) + '\n')
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, argv, output=raw)
        return raw.decode()

    def run_tolerated(self, argv, env=None, cwd=None, timeout=1800):
        """Run one allowlisted carrier-evidence command; its failure is returned, not raised."""
        from nvidia_flash_tools.workspace import tolerable_failure
        if not tolerable_failure(argv):
            raise ValueError('command failure may not be tolerated')
        if self.live:
            if self.workspace is None:
                raise ValueError('fresh authenticated locked workspace required')
            return self.workspace.run_tolerated(argv, env, cwd, timeout)
        environment = clean_env()
        environment.update(env or {})
        result = self.runner([str(x) for x in argv], cwd=cwd or self.tree,
                             env=environment, timeout=timeout, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=False)
        raw = result.stdout
        with self.audit.open('a') as log:
            log.write(json.dumps({'argv': list(map(str, argv)), 'environment': environment,
                                  'returncode': result.returncode, 'output': raw.decode(errors='replace'),
                                  'tolerated': True}) + '\n')
        return result.returncode, raw.decode(errors='replace')

    def single_rcm(self, sysfs=Path('/sys/bus/usb/devices')):
        # Refuse other NVIDIA USB devices too: conservative v1, no multi-board path.
        devices = [p.name for p in sysfs.iterdir() if (p / 'idVendor').exists()
                   and (p / 'idVendor').read_text().strip() == '0955']
        if devices != [self.port]:
            raise ValueError('require exactly one NVIDIA USB device on selected port')

    def usb_devnum(self, sysfs=Path('/sys/bus/usb/devices')):
        try:
            return (sysfs / self.port / 'devnum').read_text().strip()
        except FileNotFoundError:
            return None

    def await_reenumeration(self, before, sysfs=Path('/sys/bus/usb/devices'), timeout=120, sleep=None):
        """Wait for a fresh enumeration on the selected port after a power cycle.

        Enter can arrive before the unit actually loses power; the old device
        number is still present then, and the boot ROM is not yet answering.
        """
        import time
        sleep = sleep or time.sleep
        print('Waiting for the board to re-enumerate in Force Recovery on port ' + self.port + '...')
        for _ in range(timeout * 2):
            now = self.usb_devnum(sysfs)
            if now is not None and now != before:
                sleep(2)   # boot ROM settles after enumeration
                return
            sleep(0.5)
        raise ValueError('no fresh Force Recovery enumeration on port ' + self.port +
                         ': power-cycle the unit with the jumper fitted, then start again')

    def uid(self):
        self.single_rcm()
        raw = self.run(['./tegrarcm_v2', '--new_session', '--chip',
                        '0x' + BOARDS[self.board][4], '--instance', self.port, '--uid'],
                       cwd=self.tree / 'bootloader', timeout=30)
        return bootrom_uid(raw, self.board)

    def probe(self):
        identity = self.uid()
        bl = self.tree / 'bootloader'
        # Fresh EEPROM and full security read required on EVERY boundary.
        stale = ('cvm.bin', 'cvb.bin', 'chip_info.bin_bak', 'fuse_t234.bin', 'fuse_t264.bin')
        self.cvb_dump = None
        if self.workspace is not None:
            self.workspace.remove_generated(['bootloader/' + name for name in stale])
        else:
            for name in stale:
                (bl / name).unlink(missing_ok=True)
        if self.board == 'thor':
            self.run(['./flash.sh', '--read-info', '--usb-instance', self.port, self.alias, 'internal'])
            eeproms = {'cvm.bin':'cvm.bin', 'cvb.bin':'cvb.bin'}
        else:
            from nvidia_flash_tools.orin_recovery import fresh_eeproms
            eeproms = fresh_eeproms(self)
        module, sku, carrier, carrier_sku, _ = BOARDS[self.board]
        def decode(flag, file):
            file = eeproms.get(file, file)
            if not (bl / file).is_file():
                raise ValueError('fresh ' + file + ' missing from vendor probe')
            value = self.run(['./chkbdinfo', flag, file], cwd=bl, timeout=10).strip()
            if not value or '\n' in value:
                raise ValueError('unknown EEPROM decoder output')
            return value
        from nvidia_flash_tools import carrier as carrier_rule
        if self.board in carrier_rule.BOARDS:
            # Module identity is exactly as strict as orin-nx. The carrier has no
            # NVIDIA-format EEPROM: its cvb result is recorded and table-checked.
            if (decode('-i', 'cvm.bin'), decode('-k', 'cvm.bin')) != (module, sku):
                raise ValueError('module/SKU/carrier not allowlisted')
            prior = getattr(self, 'carrier_record', None)
            record = copy.deepcopy(prior) if prior is not None else self.cvb_evidence(bl, eeproms)
            carrier_rule.check_evidence(record)
            identity.update({'module': module + '-' + sku, 'carrier': carrier_rule.CARRIER,
                             'carrier_rule': carrier_rule.RULE, 'carrier_evidence': record,
                             'fab': decode('-f', 'cvm.bin'), 'revision': decode('-r', 'cvm.bin'),
                             'cvm_sha256': sha256(bl / eeproms['cvm.bin']),
                             'cvb_sha256': record['cvb_sha256']})
            if prior is None and record['outcome'] == 'dump-failed':
                # MB2 refuses the J401 cvb read and tegraflash stops before its
                # recovery reboot. Each tegraflash run deletes its private session
                # state, so no later run can reset the applet: only a power cycle
                # restores the boot ROM.
                if not callable(self.carrier_power_cycle):
                    raise ValueError('J401 carrier read left the MB2 applet running; power cycle required')
                print('The J401 has no NVIDIA carrier EEPROM; that read leaves NVIDIA\'s flashing applet running. '
                      'Power-cycle the unit with the Force Recovery jumper still fitted.')
                before = self.usb_devnum()
                self.carrier_power_cycle(dict(identity))
                self.await_reenumeration(before)
            # The board must be back in boot ROM recovery: the same board.
            if self.uid() != {k: identity[k] for k in ('br_cid', 'ecid')}:
                raise ValueError('board changed during carrier EEPROM read')
            if prior is None:
                self.carrier_record = copy.deepcopy(record)
        else:
            actual = (decode('-i', 'cvm.bin'), decode('-k', 'cvm.bin'),
                      decode('-i', 'cvb.bin'), decode('-k', 'cvb.bin'))
            if actual != (module, sku, carrier, carrier_sku):
                raise ValueError('module/SKU/carrier not allowlisted')
            identity.update({'module': module + '-' + sku, 'carrier': carrier + '-' + carrier_sku,
                             'fab': decode('-f', 'cvm.bin'), 'revision': decode('-r', 'cvm.bin'),
                             'cvm_sha256': sha256(bl / eeproms['cvm.bin']), 'cvb_sha256': sha256(bl / eeproms['cvb.bin'])})
        fuse = bl / ('fuse_t264.bin' if self.board == 'thor' else 'fuse_t234.bin')
        identity['fuses'] = fuse_info(fuse.read_text(), self.board)
        return identity

    def cvb_evidence(self, bl, eeproms):
        """Record the J401 cvb dump verbatim: sha256 + decode results or the exact failure."""
        import stat
        from nvidia_flash_tools import carrier as carrier_rule
        dump = self.cvb_dump
        if dump is None:
            raise ValueError('carrier EEPROM dump result missing')
        name = eeproms['cvb.bin']
        data, digest, size = None, None, None
        path = bl / name
        if dump['returncode'] == 0 and path.is_file() and not path.is_symlink():
            info = path.lstat()
            digest, size = sha256(path), info.st_size
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == carrier_rule.EEPROM_SIZE:
                data = path.read_bytes()
            else:
                data = False
        decoders = {}
        if isinstance(data, bytes):
            for flag in ('-i', '-k'):
                decoders[flag] = self.run_tolerated(['./chkbdinfo', flag, name], cwd=bl, timeout=10)
        return carrier_rule.evidence(dump_returncode=dump['returncode'], dump_output=dump['output'],
                                     data=data, sha256=digest, size=size, decoders=decoders)

    def generate_qspi(self):
        if self.board != 'thor':
            from nvidia_flash_tools.orin_recovery import command
            from nvidia_flash_tools.orin_firmware import plan, deterministic_signing, partition_guids, STOCK_XML
            signed = self.tree / 'bootloader/signed'
            snapshot = self.tree / 'bootloader/admiral-qspi-signed'
            if self.workspace is not None:
                self.workspace.validate()
            # A fresh sign must create this graph; never bless a cached cfg.
            if any(p.exists() or p.is_symlink() for p in (signed, snapshot)):
                raise ValueError('Orin signing requires a fresh signed output directory')
            # Pinned partition GUIDs and version timestamp: the same release and
            # board then sign a byte-identical QSPI image in every session.
            with deterministic_signing(self) as cfg:
                self.run(['./flash.sh', '--no-flash', '--no-systemimg', '--sign', '--qspi-only',
                          '-c', cfg, '--usb-instance', self.port, self.alias, 'internal'],
                         {'ADDITIONAL_DTB_OVERLAY': 'BootOrderNvme.dtbo'})
            # --no-flash --sign signs locally; flashcmd.txt then holds the
            # generated secureflash, which is never executed. Any other
            # operation means flash.sh did not run in generate-only mode.
            command(self, 'secureflash;reboot')
            signed = self.tree / 'bootloader/signed'
            if self.live:
                # flash.sh writes the version blob (VERFILENAME) to bootloader/,
                # not signed/; it is unsigned and its sha1 is in flash.idx.
                ver = 'qspi_bootblob_ver.txt'
                if ver in (signed/'flash.xml.tmp').read_text() and not (signed/ver).exists():
                    self.run(['/bin/cp', '--', '../' + ver, ver], cwd=signed)
                # The real R39.2.1 sign writes a complete flash.idx; regenerating
                # it drops the BCT/MB1_BCT/MEM_BCT/backup filenames. Only build
                # one when the vendor step left none (signed/ is fresh above).
                if not (signed/'flash.idx').exists():
                    self.run([self.tree/'bootloader/tegraparser_v2','--pt','flash.xml.bin',
                              '--generateflashindex','flash.idx'],cwd=signed)
                from nvidia_flash_tools.orin_firmware import pin_disk_guid
                from nvidia_flash_tools.orin_recovery import seal
                pin_disk_guid(signed, self.board)
                if self.workspace is not None:
                    seal(self)
                # T234 --rcm-boot always re-signs into signed/ (odmsign), so the
                # approved SPI graph is kept in its own copy for plan and provision.
                self.run(['/bin/cp', '-a', '--', 'signed', snapshot.name], cwd=signed.parent)
                signed = self.qspi_signed = snapshot
            stock = self.tree / STOCK_XML
            self.orin_plan, _ = plan(signed/'flash.idx', signed/'flash.xml.tmp', stock,
                                     partition_guids(self.board, stock))
            return package_hashes(self.tree)
        env = {'ADDITIONAL_DTB_OVERLAY_OPT': 'BootOrderNvme.dtbo'}
        self.run(['./l4t_initrd_flash.sh', '--no-flash', '--qspi-only', '--usb-instance', self.port, self.alias, 'internal'], env)
        xml = self.tree / 'bootloader/flash.xml'
        qspi_package(xml, self.tree / 'tools/kernel_flash/images/internal/flash.idx')
        stock = self.tree / 'bootloader/flash_l4t_t264_qspi.xml'
        allowed = set(qspi_package(stock))
        actual = qspi_package(xml)
        if len(actual) != len(set(actual)) or not set(actual) <= allowed:
            raise ValueError('unknown/duplicate partition in vendor SPI package')
        external = self.tree / 'tools/kernel_flash/images/external/flash.idx'
        if external.exists() and external.read_text().strip():
            raise ValueError('external target present in QSPI package')
        if self.board == "thor":
            from nvidia_flash_tools.firmware import bind_programmed_plan
            bind_programmed_plan(self, self.tree / "unified_flash/out/bsp_images/flash_workspace/flash-images/FileToFlash.txt")
        return package_hashes(self.tree)

    def provision_qspi(self, expected_package):
        if self.board != 'thor':
            if self.workspace is None:
                raise ValueError('authenticated workspace required for Orin firmware')
            self.workspace.validate()
            if package_hashes(self.tree) != expected_package:
                raise ValueError('Orin generated package changed after approval')
            from nvidia_flash_tools.orin_firmware import provision
            self.firmware_readback = provision(self, self.orin_transport)
            self.workspace.validate()
            return
        if self.live:
            if self.workspace is None:
                raise ValueError('authenticated locked workspace required')
            self.workspace.validate()
            if not hasattr(self.workspace, 'vendor_server'):
                raise ValueError('owned private vendor ADB server required')
            self.workspace.vendor_server.check()
        if package_hashes(self.tree) != expected_package:
            raise ValueError('vendor package changed since inspection')
        else:
            bsp = self.tree / 'unified_flash/out/bsp_images'
            from nvidia_flash_tools.firmware import plan_qspi
            index = bsp / 'flash_workspace/flash-images/FileToFlash.txt'
            plan = plan_qspi(index)
            if not hasattr(self, 'firmware_plan') or plan != self.firmware_plan:
                raise ValueError('missing/changed approved programmed firmware plan')
            self.run(['/usr/bin/python3', bsp / 'tools/flashtools/bootburn/flash_bsp_images.py',
                      '-b', 'jetson-t264', '--l4t', '-D', '-V', '-y', '-P', bsp / 'flash_workspace',
                      '--usb-instance', self.port])
            # -V requests nvdd --readback and vendor MD5 checks. Independently
            # compare exact approved input bytes on the host before recovery.
            if self.live:
                self.workspace.validate()
                if package_hashes(self.tree) != expected_package:
                    raise ValueError('firmware package mutated during provisioning')
                from nvidia_flash_tools.transport import ADB
                from nvidia_flash_tools.adb_socket import Client
                from nvidia_flash_tools.firmware import verify_qspi
                server = self.workspace.vendor_server
                identity = getattr(self, 'approved_identity', None)
                if identity is None:
                    raise ValueError('firmware readback requires approved ECID')
                transport = ADB(server.binary, identity['ecid'], self.port, server=server)
                transport.bind()
                self.firmware_readback = verify_qspi(
                    Client(server.process.pid, server.port, timeout=120), transport.serial,
                    index, self.workspace.root, plan=plan)
                self.workspace.validate()

    def ram_boot(self, expected_identity):
        # Bind both generation and execution; never re-enter the enumerable
        # top-level --flash-only wrapper after approval of one board.
        expected = {k: expected_identity[k] for k in ('br_cid', 'ecid')}
        if self.uid() != expected:
            raise ValueError('board changed before RAM generation')
        if self.board != 'thor':
            from nvidia_flash_tools.orin_recovery import ram_boot
            return ram_boot(self, expected_identity)
        env = {'BOOTIMG': str(self.tree / 'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img')}
        self.run(['./l4t_initrd_flash.sh', '--initrd', '--usb-instance', self.port,
                  '--no-flash', self.alias, 'internal'], env)
        inspect_thor_payload(self.tree)
        if self.uid() != expected:
            raise ValueError('board changed before RAM execution')
        bsp = self.tree / 'unified_flash/out/bsp_images'
        self.run(['/usr/bin/python3', bsp / 'tools/flashtools/bootburn/flash_bsp_images.py',
                  '-b', 'jetson-t264', '--l4t', '-D', '-P', bsp / 'flash_workspace',
                  '-R', '--usb-instance', self.port])


def package_hashes(tree):
    from nvidia_flash_tools.workspace import snapshot
    # Caller must still validate the live Workspace. This is a comparison digest,
    # never independent authorization for a copied mutable tree.
    graph = snapshot(Path(tree), owner=os.geteuid())
    roots_for_links = ('bootloader/', 'tools/kernel_flash/images/', 'unified_flash/out/bsp_images/')
    for name, value in graph.items():
        if value[0] == 'link' and name.startswith(('bootloader/', 'tools/kernel_flash/images/', 'unified_flash/out/bsp_images/')):
            target = (Path(tree) / name).resolve()
            domain = next(Path(tree) / root.rstrip('/') for root in roots_for_links if name.startswith(root))
            if domain not in target.parents:
                raise ValueError('package symlink escapes package domain')
    roots = ('bootloader/', 'tools/kernel_flash/images/', 'unified_flash/out/bsp_images/')
    return {name: value for name, value in graph.items() if name.startswith(roots)}


def inspect_thor_payload(tree):
    """Inspect the actual selected T264 blob, never a neighboring image.

    tegraflash_impl_t264.py:1124-1222 emits blob.xml with kernel type and
    calls tegrahost --generateblob. The pinned tool's generated fixtures
    establish blob header 80, sixteen-byte entries, payload start 1104,
    kernel type 45 and T264 sigheader length 8192 (not BUP format).
    Trust/authentication of generated files is the held Workspace's graph.
    """
    import struct
    tree = Path(tree)
    selected = tree / 'unified_flash/out/bsp_images/flash_workspace/rcm-boot/rcm_blob.bin'
    original = tree / 'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
    if not selected.is_file() or selected.is_symlink():
        raise ValueError('missing selected Thor blob')
    raw = selected.read_bytes()
    if len(raw) < 1104 or len(raw) > 512 * 1024 * 1024 or raw[:8] != b'blob\0\0\0\0':
        raise ValueError('unsupported Thor selected blob header')
    count = struct.unpack_from('<I', raw, 76)[0]
    if not 1 <= count <= 64:
        raise ValueError('invalid Thor blob entry count')
    entries, cursor, kinds = [], 1104, set()
    for i in range(count):
        kind, offset, length = struct.unpack_from('<IQI', raw, 80 + i * 16)
        if kind in kinds or offset != cursor or not length or length > len(raw) - offset:
            raise ValueError('invalid/overlapping Thor blob entries')
        kinds.add(kind)
        entries.append((kind, offset, length))
        cursor += length
    if cursor != len(raw) or any(raw[80 + count * 16:1104]):
        raise ValueError('Thor blob trailing/unknown manifest data')
    kernels = [(offset, length) for kind, offset, length in entries if kind == 45]
    if len(kernels) != 1:
        raise ValueError('exactly one selected Thor kernel required')
    offset, length = kernels[0]
    kernel = raw[offset:offset + length]
    boot = original.read_bytes()
    if not boot.startswith(b'ANDROID!') or len(kernel) < 8192 or kernel[:4] != b'NVDA':
        raise ValueError('unsupported Thor signed boot image')
    payload = kernel[8192:]
    if payload[:len(boot)] != boot or len(payload) - len(boot) not in range(16) or any(payload[len(boot):]):
        raise ValueError('selected Thor kernel differs from authenticated flashing boot image')
    return {'blob_sha256': hashlib.sha256(raw).hexdigest(),
            'boot_sha256': hashlib.sha256(boot).hexdigest(),
            'signed_kernel_sha256': hashlib.sha256(kernel).hexdigest()}


def thor_flash_graph(index):
    """R39.2.1 bootburn_adb.py:122-141 twelve space-separated fields.

    EraseQspi:1366-1388 erases a complete matching SPI controller; only the
    primary devkit controller is permitted. External storage and second die
    are intentionally not supported. This parser is not hardware approval.
    """
    index = Path(index)
    from nvidia_flash_tools.security import regular_graph
    regular_graph(index.parent)
    rows, names, ranges = [], set(), []
    for line in index.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split(' ')
        if len(fields) != 12 or any(not f for f in fields):
            raise ValueError('unsupported FileToFlash format')
        device, name, filename, start, size, blocks, resize, sku, bch, header, md5, rw = fields
        if device != '/dev/block/810c5b0000.spi':
            raise ValueError('non-SPI or unapproved erase target in FileToFlash')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in names:
            raise ValueError('duplicate/unknown flash partition')
        if not all(re.fullmatch('[0-9]+', v) for v in (start, size, blocks, resize, sku, header, rw)):
            raise ValueError('unsupported flash range/flags')
        start, size = int(start), int(size)
        if not size or start % 512 or size % 512 or start + size > 64 * 1024 * 1024:
            raise ValueError('SPI range outside approved capacity')
        if resize != '0' or sku != '0' or rw != '1':
            raise ValueError('unsupported mutable flash operation')
        relative = Path(filename)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('flash reference escapes package')
        target = index.parent / relative
        if not target.is_file() or target.is_symlink() or target.stat().st_size > size:
            raise ValueError('flash reference missing/oversized')
        if not re.fullmatch('[0-9a-f]{32}', md5) or hashlib.md5(target.read_bytes()).hexdigest() != md5:
            raise ValueError('flash reference MD5 mismatch')
        names.add(name)
        ranges.append((start, start + size))
        rows.append(fields)
    if not rows:
        raise ValueError('empty FileToFlash graph')
    ordered = sorted(ranges)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('overlapping SPI ranges')
    return rows
