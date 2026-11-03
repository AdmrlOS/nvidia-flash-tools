"""Authenticated board-specific vendor-tree inputs (Seeed reComputer J40/J4012 only).

The inputs come from the Admiral BSP (``board/admiral/boards/recomputer-j40/flash``):
the MB2 BCT patch, the ``recomputer-j40-qspi`` flash configuration and the J401
device trees. They ship inside the authenticated bundle; ``release.json`` pins
every byte. Installation happens once, in the fresh private workspace, right
after the pinned NVIDIA BSP is extracted and before the first vendor execution,
and the resulting tree becomes the workspace's expected graph.
"""
import hashlib
import os
import posixpath
from pathlib import Path
import re
import stat

BOARDS = ('recomputer-j40',)
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


def _read(root, record, kind, install):
    if not isinstance(record, dict):
        raise ValueError('invalid ' + kind + ' vendor input record')
    path = record.get('path')
    if (not isinstance(path, str) or not path.startswith(ROOT_PREFIX) or '..' in path.split('/') or
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


def install(workspace, release, board, root):
    """Apply the pinned inputs to the fresh prepared tree; no-op for other boards."""
    inputs = load(release, board, root)
    if inputs is None:
        return None
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
