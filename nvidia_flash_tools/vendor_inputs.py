"""Authenticated board-specific vendor-tree inputs (recomputer-j40, mic-733-ao).

The inputs come from the Admiral BSP (``board/admiral/boards/<board>/flash``)
and that board's build output (per-SKU DTBs). They ship inside the
authenticated bundle; ``release.json`` pins every byte. Installation happens
once, in the fresh private workspace, right after the pinned NVIDIA BSP is
extracted and before the first vendor execution, and the resulting tree
becomes the workspace's expected graph.

* recomputer-j40: MB2 BCT patch (applied to NVIDIA's common dtsi), the
  ``recomputer-j40-qspi`` flash configuration, the J401 DTBs and camera DTBO.
* mic-733-ao: the ``mic-733-ao-qspi`` flash configuration, an MB2 misc BCT
  (``cvb_eeprom_read_size = <0>``) installed beside NVIDIA's, two MB1 files
  created from NVIDIA's a04 pinmux/GPIO files by the pinned patch, and the
  three MIC-733-AO per-SKU DTBs. NVIDIA's own files are never modified; the
  NVIDIA files the configuration derives from are SHA256-checked first.
"""
import hashlib
import os
import posixpath
from pathlib import Path
import re
import stat

BOARDS = ('recomputer-j40', 'mic-733-ao')
ROOT_PREFIX = 'vendor-inputs/recomputer-j40/'
MB2_TARGET = 'bootloader/tegra234-mb2-bct-common.dtsi'
CONF_INSTALL = 'recomputer-j40-qspi.conf'
RECOVERY_CONF_INSTALL = 'recomputer-j40-recovery.conf'
DTB_INSTALL = tuple('kernel/dtb/tegra234-j401-p3768-0000+p3767-' + sku + '-recomputer.dtb'
                    for sku in ('0000', '0001', '0003', '0004'))
DTBO_INSTALL = ('kernel/dtb/tegra234-p3767-camera-p3768-imx219-dual-seeed.dtbo',)
# NVIDIA files the configuration refers to (flash-qspi.sh NVIDIA_REQUIRED).
REQUIRED_NVIDIA = (
    'flash.sh', 'p3768-0000-p3767-0000-a0.conf', 'p3767.conf.common',
    'bootloader/generic/cfg/flash_t234_qspi.xml',
    'bootloader/generic/BCT/tegra234-mb1-bct-pinmux-p3767-hdmi-a03.dtsi',
    'bootloader/generic/BCT/tegra234-mb1-bct-padvoltage-p3767-hdmi-a03.dtsi',
    'bootloader/tegra234-mb1-bct-gpio-p3767-hdmi-a03.dtsi',
    'bootloader/generic/tegra234-bpmp-3767-0000-3768-super.dtb',
    'bootloader/generic/tegra234-bpmp-3767-0001-3768-super.dtb',
    'bootloader/generic/tegra234-bpmp-3767-0003-3768-super.dtb',
    'bootloader/generic/tegra234-bpmp-3767-0004-3768-super.dtb',
    'kernel/dtb/tegra234-dcb-p3767-0000-hdmi.dtbo')
MAX_INPUT = 4 * 1024 * 1024
_HEX = re.compile('[0-9a-f]{64}')

# Advantech MIC-733-AO (board/admiral/boards/mic-733-ao/flash, flash-qspi.sh).
MIC733_PREFIX = 'vendor-inputs/mic-733-ao/'
MIC733_CONF_INSTALL = 'mic-733-ao-qspi.conf'
MIC733_RECOVERY_CONF_INSTALL = 'mic-733-ao-recovery.conf'
MIC733_MB2_INSTALL = 'bootloader/generic/BCT/tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts'
MIC733_DTB_INSTALL = tuple('kernel/dtb/tegra234-mic-733-ao+p3701-' + sku + '.dtb' for sku in ('0000', '0004', '0005'))
# (NVIDIA stock source, created copy) for the MB1 patch; the patch's file
# headers name the copies. Same pairs as flash-qspi.sh PINMUX_*/GPIO_*.
MIC733_MB1_FILES = (
    ('bootloader/tegra234-mb1-bct-gpio-p3701-0000-a04.dtsi',
     'bootloader/tegra234-mb1-bct-gpio-p3701-0000-a04-mic-733-ao.dtsi'),
    ('bootloader/generic/BCT/tegra234-mb1-bct-pinmux-p3701-0000-a04.dtsi',
     'bootloader/generic/BCT/tegra234-mb1-bct-pinmux-p3701-0000-a04-mic-733-ao.dtsi'))
# NVIDIA R39.2.1 files the configuration derives from or relies on, pinned by
# SHA256 in release.json (flash-qspi.sh NVIDIA_SHA; the MB1 sources are pinned
# with their patch record). The MB2 common dtsi is included by the MB2 misc BCT.
MIC733_NVIDIA_PINNED = ('p3737-0000-p3701-0000.conf', 'p3701.conf.common',
                        'bootloader/generic/BCT/tegra234-mb1-bct-padvoltage-p3701-0000-a04.dtsi',
                        'bootloader/tegra234-mb2-bct-common.dtsi')
# Other NVIDIA files the configuration refers to (flash-qspi.sh NVIDIA_REQUIRED).
MIC733_REQUIRED_NVIDIA = ('flash.sh', 'bootloader/generic/cfg/flash_t234_qspi.xml',
                          'bootloader/generic/BCT/tegra234-mb1-bct-pmic-p3701-0005.dts',
                          'bootloader/generic/tegra234-bpmp-3701-0000-3737-0000.dtb',
                          'bootloader/generic/tegra234-bpmp-3701-0004-3737-0000.dtb',
                          'bootloader/generic/tegra234-bpmp-3701-0005-3737-0000.dtb')


def apply_unified_diff(original, patch, target):
    """Apply a single-file unified diff exactly (no fuzz, offsets or renames).

    Free text before the first ``--- `` line (the BSP patch's description) is
    ignored; everything from the file headers on must match ``target`` and the
    original lines or the patch is refused.
    """
    lines = patch.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.startswith('--- ')), None)
    if start is None or start + 1 >= len(lines) or not lines[start + 1].startswith('+++ '):
        raise ValueError('MB2 patch has no file headers')
    if (lines[start].rstrip('\n').split('\t')[0] != '--- a/' + target or
            lines[start + 1].rstrip('\n').split('\t')[0] != '+++ b/' + target):
        raise ValueError('MB2 patch does not target ' + target)
    source = original.splitlines(keepends=True)
    result, cursor, i, hunks = [], 0, start + 2, 0
    while i < len(lines):
        match = re.fullmatch(r'@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@.*\n?', lines[i])
        if not match:
            raise ValueError('unsupported MB2 patch content')
        old_start, old_count, _, new_count = map(int, match.groups())
        if old_start - 1 < cursor:
            raise ValueError('overlapping MB2 patch hunks')
        result.extend(source[cursor:old_start - 1])
        cursor = old_start - 1
        i += 1
        seen_old = seen_new = 0
        while i < len(lines) and not lines[i].startswith('@@ '):
            text = lines[i]
            tag, body = text[:1], text[1:]
            if tag == ' ':
                if cursor >= len(source) or source[cursor] != body:
                    raise ValueError('MB2 patch context does not match')
                result.append(body); cursor += 1; seen_old += 1; seen_new += 1
            elif tag == '-':
                if cursor >= len(source) or source[cursor] != body:
                    raise ValueError('MB2 patch removal does not match')
                cursor += 1; seen_old += 1
            elif tag == '+':
                result.append(body); seen_new += 1
            else:
                raise ValueError('unsupported MB2 patch line')
            i += 1
        if (seen_old, seen_new) != (old_count, new_count):
            raise ValueError('MB2 patch hunk counts differ')
        hunks += 1
    if not hunks:
        raise ValueError('MB2 patch has no hunks')
    result.extend(source[cursor:])
    return ''.join(result)


def split_unified_diff(patch):
    """Split a multi-file unified diff into {target: single-file diff}, exactly.

    Each section must be ``--- a/X`` / ``+++ b/X`` followed by complete hunks
    (counted, so a removed line that starts with ``--`` cannot end a section).
    Free text before the first header is ignored, as by apply_unified_diff.
    """
    lines = patch.splitlines(keepends=True)
    i = next((n for n, line in enumerate(lines) if line.startswith('--- ')), None)
    if i is None:
        raise ValueError('MB1 patch has no file headers')
    sections = {}
    while i < len(lines):
        old = lines[i].rstrip('\n').split('\t')[0]
        new = lines[i + 1].rstrip('\n').split('\t')[0] if i + 1 < len(lines) else ''
        if not old.startswith('--- a/') or new != '+++ b/' + old[6:]:
            raise ValueError('unsupported MB1 patch file header')
        target, start = old[6:], i
        i += 2
        hunks = 0
        while i < len(lines) and lines[i].startswith('@@ '):
            match = re.fullmatch(r'@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@.*\n?', lines[i])
            if not match:
                raise ValueError('unsupported MB1 patch hunk header')
            want_old, want_new = int(match[2]), int(match[4])
            i += 1
            seen_old = seen_new = 0
            while seen_old < want_old or seen_new < want_new:
                if i >= len(lines):
                    raise ValueError('truncated MB1 patch hunk')
                tag = lines[i][:1]
                if tag == ' ':
                    seen_old += 1; seen_new += 1
                elif tag == '-':
                    seen_old += 1
                elif tag == '+':
                    seen_new += 1
                else:
                    raise ValueError('unsupported MB1 patch line')
                i += 1
            if (seen_old, seen_new) != (want_old, want_new):
                raise ValueError('MB1 patch hunk counts differ')
            hunks += 1
        if not hunks or target in sections:
            raise ValueError('empty or duplicate MB1 patch section')
        sections[target] = ''.join(lines[start:i])
    return sections


def _read(root, record, kind, install, prefix=ROOT_PREFIX):
    if not isinstance(record, dict):
        raise ValueError('invalid ' + kind + ' vendor input record')
    path = record.get('path')
    if (not isinstance(path, str) or not path.startswith(prefix) or '..' in path.split('/') or
            '//' in path or not re.fullmatch(r'[A-Za-z0-9_.+/-]+', path)):
        raise ValueError('invalid ' + kind + ' vendor input path')
    size = record.get('size')
    if (not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_INPUT or
            not _HEX.fullmatch(str(record.get('sha256')))):
        raise ValueError('invalid ' + kind + ' vendor input pin')
    if install is not None and record.get('install') != install:
        raise ValueError('unexpected ' + kind + ' vendor input destination')
    root = Path(root)
    source = root / path
    if any(p.is_symlink() for p in (source, *source.parents) if p != root and root in p.parents):
        raise ValueError('vendor input symlink refused')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('vendor input must be a regular file: ' + path)
        data = b''
        while block := os.read(fd, 1024 * 1024):
            data += block
            if len(data) > MAX_INPUT:
                raise ValueError('vendor input oversized: ' + path)
    finally:
        os.close(fd)
    if len(data) != size or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('vendor input size/SHA256 mismatch: ' + path)
    return data


def rootfs_members(data):
    """The pinned sample-rootfs subset: one archive member name per line."""
    text = data.decode()
    names = (text[:-1] if text.endswith('\n') else text).split('\n')
    if not names or names != sorted(set(names)) or any(
            not n or n.startswith('/') or '..' in n.split('/') or n != posixpath.normpath(n) for n in names):
        raise ValueError('invalid pinned sample-rootfs member list')
    return frozenset(names)


def load(release, board, root):
    """Return verified bytes for every pinned input of ``board`` (None if it has none)."""
    record = release['boards'][board].get('vendor_inputs')
    if board not in BOARDS:
        if record is not None:
            raise ValueError('unexpected vendor inputs for ' + board)
        return None
    if board == 'mic-733-ao':
        return _load_mic733(record, root)
    if not isinstance(record, dict) or set(record) != {'source', 'mb2_patch', 'config', 'recovery_config',
                                                       'sample_rootfs_members', 'dtbs', 'dtbos'}:
        raise ValueError('missing/unsupported recomputer-j40 vendor input record')
    patch = record['mb2_patch']
    if (not isinstance(patch, dict) or set(patch) != {'target', 'patch', 'stock_sha256', 'patched_sha256'} or
            patch['target'] != MB2_TARGET or not _HEX.fullmatch(str(patch['stock_sha256'])) or
            not _HEX.fullmatch(str(patch['patched_sha256']))):
        raise ValueError('invalid MB2 patch record')
    if (not isinstance(record['dtbs'], list) or not isinstance(record['dtbos'], list) or
            len(record['dtbs']) != len(DTB_INSTALL) or len(record['dtbos']) != len(DTBO_INSTALL)):
        raise ValueError('unexpected J401 device tree set')
    return {'patch': _read(root, patch['patch'], 'MB2 patch', None),
            'config': _read(root, record['config'], 'config', CONF_INSTALL),
            'recovery_config': _read(root, record['recovery_config'], 'recovery config', RECOVERY_CONF_INSTALL),
            'rootfs_members': rootfs_members(_read(root, record['sample_rootfs_members'], 'rootfs members', None)),
            'dtbs': [(name, _read(root, item, 'dtb', name)) for name, item in zip(DTB_INSTALL, record['dtbs'])],
            'dtbos': [(name, _read(root, item, 'dtbo', name)) for name, item in zip(DTBO_INSTALL, record['dtbos'])],
            'mb2': patch}


def _load_mic733(record, root):
    if not isinstance(record, dict) or set(record) != {'source', 'config', 'recovery_config', 'sample_rootfs_members',
                                                       'mb2_bct', 'mb1_patch', 'nvidia_sha256', 'dtbs'}:
        raise ValueError('missing/unsupported mic-733-ao vendor input record')
    read = lambda item, kind, install=None: _read(root, item, kind, install, MIC733_PREFIX)
    pinned = record['nvidia_sha256']
    if (not isinstance(pinned, dict) or set(pinned) != set(MIC733_NVIDIA_PINNED) or
            not all(_HEX.fullmatch(str(value)) for value in pinned.values())):
        raise ValueError('invalid mic-733-ao NVIDIA file pins')
    mb1 = record['mb1_patch']
    if not isinstance(mb1, dict) or set(mb1) != {'patch', 'files'} or not isinstance(mb1['files'], list):
        raise ValueError('invalid MB1 patch record')
    files = []
    for (source, target), item in zip(MIC733_MB1_FILES, mb1['files']):
        if (not isinstance(item, dict) or set(item) != {'source', 'target', 'stock_sha256', 'patched_sha256'} or
                (item['source'], item['target']) != (source, target) or
                not _HEX.fullmatch(str(item['stock_sha256'])) or not _HEX.fullmatch(str(item['patched_sha256']))):
            raise ValueError('invalid MB1 patch file record')
        files.append(dict(item))
    if len(files) != len(MIC733_MB1_FILES) or len(mb1['files']) != len(MIC733_MB1_FILES):
        raise ValueError('unexpected MB1 patch file set')
    patch = read(mb1['patch'], 'MB1 patch')
    try:
        sections = split_unified_diff(patch.decode())
    except UnicodeDecodeError as exc:
        raise ValueError('MB1 patch is not text') from exc
    if set(sections) != {target for _, target in MIC733_MB1_FILES}:
        raise ValueError('MB1 patch does not target exactly the MIC-733-AO MB1 copies')
    if not isinstance(record['dtbs'], list) or len(record['dtbs']) != len(MIC733_DTB_INSTALL):
        raise ValueError('unexpected MIC-733-AO device tree set')
    return {'board': 'mic-733-ao',
            'config': read(record['config'], 'config', MIC733_CONF_INSTALL),
            'recovery_config': read(record['recovery_config'], 'recovery config', MIC733_RECOVERY_CONF_INSTALL),
            'rootfs_members': rootfs_members(read(record['sample_rootfs_members'], 'rootfs members')),
            'mb2_bct': read(record['mb2_bct'], 'MB2 BCT', MIC733_MB2_INSTALL),
            'mb1': {'patch': patch, 'sections': sections, 'files': files},
            'nvidia_sha256': dict(pinned),
            'dtbs': [(name, read(item, 'dtb', name)) for name, item in zip(MIC733_DTB_INSTALL, record['dtbs'])]}


def _install_mic733(workspace, inputs, board):
    workspace.validate()
    tree = workspace.tree
    def inside(relative):
        path = tree / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(tree.resolve()):
            raise ValueError('not the pinned NVIDIA tree; missing ' + relative)
        return path
    for relative in MIC733_REQUIRED_NVIDIA:
        inside(relative)
    for relative, expected in inputs['nvidia_sha256'].items():
        if hashlib.sha256(inside(relative).read_bytes()).hexdigest() != expected:
            raise ValueError(relative + ' sha256 differs from the pinned NVIDIA R39.2.1 file '
                             '(modified tree, or another board\'s recipe applied?)')
    created = []
    for item in inputs['mb1']['files']:
        stock = inside(item['source']).read_bytes()
        if hashlib.sha256(stock).hexdigest() != item['stock_sha256']:
            raise ValueError('stock ' + item['source'] + ' sha256 differs from the pinned NVIDIA R39.2.1 file')
        try:
            patched = apply_unified_diff(stock.decode(), inputs['mb1']['sections'][item['target']],
                                         item['target']).encode()
        except UnicodeDecodeError as exc:
            raise ValueError('MB1 BCT is not text') from exc
        if hashlib.sha256(patched).hexdigest() != item['patched_sha256']:
            raise ValueError('patched ' + item['target'] + ' sha256 differs from the pinned result')
        created.append((item['target'], patched))
    files = [(MIC733_CONF_INSTALL, inputs['config']), (MIC733_RECOVERY_CONF_INSTALL, inputs['recovery_config']),
             (MIC733_MB2_INSTALL, inputs['mb2_bct']), *created, *inputs['dtbs']]
    for relative, _ in files:
        path = tree / relative
        if path.exists() or path.is_symlink():
            raise ValueError('vendor input destination already exists: ' + relative)
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise ValueError('vendor input destination directory missing: ' + relative)
    for relative, data in files:
        with (tree / relative).open('xb') as stream:
            stream.write(data)
        (tree / relative).chmod(0o644)
    from nvidia_flash_tools.workspace import snapshot
    workspace._seal_modes()
    workspace.expected = snapshot(tree, workspace.owner)
    summary = {'board': board,
               'nvidia_sha256': dict(inputs['nvidia_sha256']),
               'mb1': {'patch_sha256': hashlib.sha256(inputs['mb1']['patch']).hexdigest(),
                       'files': [dict(item) for item in inputs['mb1']['files']]},
               'installed': {name: hashlib.sha256(data).hexdigest() for name, data in files}}
    workspace.inputs['vendor_inputs'] = summary
    workspace.record('vendor-inputs')
    return summary


def install(workspace, release, board, root):
    """Apply the pinned inputs to the fresh prepared tree; no-op for other boards."""
    inputs = load(release, board, root)
    if inputs is None:
        return None
    if inputs.get('board') == 'mic-733-ao':
        return _install_mic733(workspace, inputs, board)
    workspace.validate()
    tree = workspace.tree
    for relative in REQUIRED_NVIDIA:
        path = tree / relative
        if not path.exists() or not path.resolve().is_relative_to(tree.resolve()):
            raise ValueError('not the pinned NVIDIA tree; missing ' + relative)
    files = [(CONF_INSTALL, inputs['config']), (RECOVERY_CONF_INSTALL, inputs['recovery_config']),
             *inputs['dtbs'], *inputs['dtbos']]
    for relative, _ in files:
        path = tree / relative
        if path.exists() or path.is_symlink():
            raise ValueError('vendor input destination already exists: ' + relative)
    mb2 = tree / MB2_TARGET
    if mb2.is_symlink() or not mb2.is_file():
        raise ValueError('missing stock MB2 BCT file')
    stock = mb2.read_bytes()
    record = inputs['mb2']
    if hashlib.sha256(stock).hexdigest() != record['stock_sha256']:
        raise ValueError('stock MB2 BCT sha256 differs from the pinned NVIDIA R39.2.1 file')
    try:
        patched = apply_unified_diff(stock.decode(), inputs['patch'].decode(), MB2_TARGET).encode()
    except UnicodeDecodeError as exc:
        raise ValueError('MB2 BCT/patch is not text') from exc
    if hashlib.sha256(patched).hexdigest() != record['patched_sha256']:
        raise ValueError('patched MB2 BCT sha256 differs from the pinned result')
    mode = stat.S_IMODE(mb2.stat().st_mode)
    mb2.write_bytes(patched)
    mb2.chmod(mode)
    for relative, data in files:
        with (tree / relative).open('xb') as stream:
            stream.write(data)
        (tree / relative).chmod(0o644)
    from nvidia_flash_tools.workspace import snapshot
    workspace._seal_modes()
    workspace.expected = snapshot(tree, workspace.owner)
    summary = {'board': board,
               'mb2': {'target': MB2_TARGET, 'stock_sha256': record['stock_sha256'],
                       'patched_sha256': record['patched_sha256'],
                       'patch_sha256': hashlib.sha256(inputs['patch']).hexdigest()},
               'installed': {name: hashlib.sha256(data).hexdigest() for name, data in files}}
    workspace.inputs['vendor_inputs'] = summary
    workspace.record('vendor-inputs')
    return summary
