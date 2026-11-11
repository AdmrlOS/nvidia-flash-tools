"""R39.2.1 Orin SPI-only signed-package and full-controller verification.

Matches l4t_flash_from_kernel.sh write_to_spi_partition, including 16KiB
BR-BCT repetition. This is NOT Thor's 256KiB BCT transformation.
"""
import contextlib
import csv
import hashlib
from pathlib import Path
import re
import shlex
import uuid
from nvidia_flash_tools.vendor import qspi_package

CAPACITY = 64 * 1024 * 1024
EXECUTOR_TIMEOUT = 3600
# Accepted /sys/class/mtd/mtd0 values. The erase block only has to divide the
# device (it is erased whole and read back in full): 4 KiB measured on a J4012
# (Orin NX); 64 KiB is the common NOR block size.
GEOMETRY = (('size', (str(CAPACITY),)), ('erasesize', ('4096', '65536')), ('type', ('nor',)))
# Boards whose module QSPI geometry has never been measured on real hardware
# (AGX Orin P3701-0005 in the MIC-733-AO): the RAM-only recovery reads mtd0 and
# shows it BEFORE the firmware approval, and an unacceptable value stops there
# instead of after the operator approved the erase. Remove a board once its
# first RAM-only probe has recorded the values (keep provision's check).
MEASURE_BEFORE_APPROVAL = ('mic-733-ao',)
GEOMETRY_FIELDS = ('name', 'type', 'size', 'erasesize', 'writesize')
CHUNK = 4 * 1024 * 1024
# One board-side pass reads and hashes all 16 chunks (mtd_debug + sha256sum).
HASH_TIMEOUT = 600

STOCK_XML = 'bootloader/generic/cfg/flash_t234_qspi.xml'
PINNED_XML = 'bootloader/generic/cfg/admiral-flash_t234_qspi.xml'
# Deterministic QSPI generation for one release + board.
# tegraparser_v2 draws every GPT partition unique GUID from srand(time()) unless
# the partition XML carries <unique_guid>; each partition gets
# uuid5(GUID_NAMESPACE, '<board>:<partition name>'). The namespace is a fixed
# constant private to this installer, so the values cannot equal NVIDIA's or
# any NVMe partition GUID.
GUID_NAMESPACE = uuid.UUID('6cc68acf-9941-4188-b54d-f0b2db39db6d')
# flash.sh writes $(date -R) into qspi_bootblob_ver.txt (A_VER/B_VER). Pin it to
# the R39.2.1 build date from its nv_tegra_release (GCID 46758480, Fri Aug 7
# 05:42:45 UTC 2026); both lines are replaced so the host time zone cannot
# change the derived %Y%m%d%H%M%S value either.
VER_TIMESTAMP_SITE = ('\tVER_TIMESTAMP="$(date -R)"\n'
                      '\tTIMESTAMP=$(date -d "$VER_TIMESTAMP" +%Y%m%d%H%M%S)\n')
VER_TIMESTAMP_PINNED = ('\tVER_TIMESTAMP="Fri, 07 Aug 2026 05:42:45 +0000"\n'
                        '\tTIMESTAMP=20260807054245\n')


# tegraparser_v2 seeds the GPT *disk* GUID from srand(time(NULL)) with no XML
# or command-line override, so it is pinned after signing in the two flashed
# secondary GPT copies (header CRC and their flash.idx sha1 rewritten to match).
GPT_FILES = ('gpt_secondary_3_0.bin', 'gpt_backup_secondary_3_0.bin')
GPT_FILE_SIZE = 16384 + 512   # 128 entries x 128 bytes, then the 92-byte header


def disk_guid(board):
    return uuid.uuid5(GUID_NAMESPACE, board + ':disk')


def pin_disk_guid(signed, board):
    """Set the pinned disk GUID in the signed secondary GPTs; keep flash.idx exact."""
    import struct
    import zlib
    guid = disk_guid(board).bytes_le
    index = Path(signed) / 'flash.idx'
    lines = index.read_text().splitlines(keepends=True)
    for name in GPT_FILES:
        path = Path(signed) / name
        listed = [line for line in lines if [f.strip() for f in line.split(',')][4:5] == [name]]
        if not listed and not (path.exists() or path.is_symlink()):
            continue            # not part of this signed graph; nothing flashed to pin
        if path.is_symlink() or not path.is_file():
            raise ValueError('signed Orin secondary GPT missing: ' + name)
        data = bytearray(path.read_bytes())
        h = GPT_FILE_SIZE - 512
        if len(data) != GPT_FILE_SIZE or data[h:h + 8] != b'EFI PART' or struct.unpack_from('<I', data, h + 12)[0] != 92:
            raise ValueError('unknown signed Orin secondary GPT layout: ' + name)
        def crc(buffer):
            header = bytearray(buffer[h:h + 92]); header[16:20] = bytes(4)
            return zlib.crc32(header) & 0xFFFFFFFF
        if crc(data) != struct.unpack_from('<I', data, h + 16)[0]:
            raise ValueError('signed Orin secondary GPT header CRC invalid: ' + name)
        old = hashlib.sha1(data).hexdigest()
        data[h + 56:h + 72] = guid
        struct.pack_into('<I', data, h + 16, crc(data))
        new = hashlib.sha1(data).hexdigest()
        rows = [i for i, line in enumerate(lines)
                if [f.strip() for f in line.split(',')][4:5] == [name] and line.rstrip().endswith(', ' + old)]
        if len(rows) != 1:
            raise ValueError('signed Orin flash.idx row not uniquely found for ' + name)
        line = lines[rows[0]]; body = line.rstrip('\r\n')
        lines[rows[0]] = body[:-len(old)] + new + line[len(body):]
        path.write_bytes(data)
    index.write_text(''.join(lines))


def partition_guids(board, stock):
    """Deterministic <unique_guid> for every stock partition of this board."""
    return {name: str(uuid.uuid5(GUID_NAMESPACE, board + ':' + name)) for name in qspi_package(stock)}


def pinned_xml(stock, board):
    """Stock QSPI XML text with exactly one <unique_guid> added per partition.

    Text insertion keeps every stock byte; the result is re-parsed and must
    differ from stock only by those elements.
    """
    import xml.etree.ElementTree as ET
    text = Path(stock).read_text()
    guids = partition_guids(board, stock)
    if 'unique_guid' in text:
        raise ValueError('stock Orin SPI XML already carries unique GUIDs')
    pattern = re.compile(r'<partition\s+name="([A-Za-z0-9_-]+)"[^>]*(?<!/)>')
    if len(pattern.findall(text)) != len(guids):
        raise ValueError('stock Orin SPI XML partition tags not uniquely located')
    result = pattern.sub(lambda m: m[0] + '\n            <unique_guid> ' + guids[m[1]] + ' </unique_guid>', text)
    # qspi_package (via partition_guids) already refused entities/DTDs here.
    root = ET.fromstring(result)
    for node in root.findall('.//partition'):
        values = [(g.text or '').strip() for g in node.findall('unique_guid')]
        if values != [guids[node.get('name')]]:
            raise ValueError('pinned Orin SPI XML unique GUID placement failed')
    return result


def _seal(vendor):
    if vendor.workspace is not None:
        from nvidia_flash_tools.orin_recovery import seal
        seal(vendor)


@contextlib.contextmanager
def deterministic_signing(vendor):
    """Write the pinned XML and pin flash.sh's version timestamp while signing.

    Yields the XML path for flash.sh -c. flash.sh is restored (and the tree
    re-sealed) even if signing fails.
    """
    flash = vendor.tree / 'flash.sh'
    original = flash.read_text()
    if original.count(VER_TIMESTAMP_SITE) != 1:
        raise ValueError('pinned flash.sh version timestamp site changed')
    target = vendor.tree / PINNED_XML
    if target.is_symlink():
        raise ValueError('pinned Orin SPI XML path is a symlink')
    target.write_text(pinned_xml(vendor.tree / STOCK_XML, vendor.board))
    flash.write_text(original.replace(VER_TIMESTAMP_SITE, VER_TIMESTAMP_PINNED))
    _seal(vendor)
    try:
        yield PINNED_XML
    finally:
        flash.write_text(original); _seal(vendor)


def plan(index, xml, stock, guids=None):
    names = qspi_package(xml, index)
    allowed = qspi_package(stock)
    # qspi_package rejects entities/DTDs and bounds these authenticated XMLs.
    import xml.etree.ElementTree as ET
    configured = {p.get('name'):p for p in ET.parse(xml).findall('.//device/partition')}
    original = {p.get('name'):p for p in ET.parse(stock).findall('.//device/partition')}
    for name,node in configured.items():
        base=original.get(name)
        if base is None or node.attrib != base.attrib:
            raise ValueError('Orin stock partition attributes changed')
        for tag in ('size','allocation_policy','filesystem_type','allocation_attribute','align_boundary'):
            actual=(node.findtext(tag) or '').strip()
            value=(base.findtext(tag) or '').strip()
            if actual != value:
                raise ValueError('Orin stock partition geometry changed')
        # The only permitted addition to stock: the pinned per-partition GUID.
        unique = [(g.text or '').strip() for g in node.findall('unique_guid')]
        if base.findall('unique_guid') or unique != ([] if guids is None else [guids.get(name)]):
            raise ValueError('Orin SPI partition unique GUID differs from the pinned value')
    if len(names) != len(set(names)) or set(names) != set(allowed):
        raise ValueError('Orin SPI layout must preserve exact stock partition names')
    root = Path(index).parent
    expected = bytearray(b'\xff' * CAPACITY)
    rows, seen, extents, payloads = [], set(), [], []
    for row in csv.reader(Path(index).read_text().splitlines(), skipinitialspace=True):
        if len(row) != 8 or not re.fullmatch(r'3:0:[A-Za-z0-9_-]+', row[1]):
            raise ValueError('unsupported Orin signed flash index')
        name = row[1].split(':')[2]
        # Rows with no payload (smm-fw, reserved, uefi_variables, ...) carry an
        # empty filename, length and sha1; the vendor writer skips them.
        empty = row[4] == row[5] == row[7] == ''
        if name not in names or name in seen or not all(re.fullmatch('[0-9]+', row[i]) for i in (0, 2, 3)) \
                or not (empty or re.fullmatch('[0-9]+', row[5])):
            raise ValueError('duplicate/unknown Orin partition or range')
        start, size, length = int(row[2]), int(row[3]), int(row[5] or 0)
        if size <= 0 or start % 512 or size % 512 or start + size > CAPACITY:
            raise ValueError('Orin partition outside SPI')
        configured_size=(configured[name].findtext('size') or '').strip()
        if configured_size and int(configured_size,0) not in (0,size,0xffffffffffffffff):
            raise ValueError('Orin index/XML partition size mismatch')
        seen.add(name); extents.append((start, start + size)); rows.append(row)
        filename = row[4]
        if (configured[name].findtext('filename') or '').strip() != filename:
            raise ValueError('Orin signed XML/index payload disagreement')
        if not filename:
            if length:
                raise ValueError('missing generated firmware payload')
            continue
        if Path(filename).name != filename or filename in ('.', '..'):
            raise ValueError('firmware payload escapes signed directory')
        path = root / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing regular generated firmware payload')
        data = path.read_bytes()
        if not data or len(data) != length or length > size or hashlib.sha1(data).hexdigest() != row[7]:
            raise ValueError('generated partition length/hash mismatch')
        if data[:4] == b'\x3a\xff\x26\xed':
            raise ValueError('sparse SPI payload refused')
        offsets = [start]
        if name == 'BCT':
            if start != 0 or size % 16384 or length > 16384:
                raise ValueError('unknown Orin BR-BCT placement')
            offsets = list(range(0, size, 16384))
        for offset in offsets:
            expected[offset:offset + length] = data
        payloads.append({'partition':name, 'filename':filename, 'offsets':offsets,
                         'size':length, 'sha256':hashlib.sha256(data).hexdigest()})
    ordered = sorted(extents)
    if seen != set(names) or any(a[1] > b[0] for a,b in zip(ordered,ordered[1:])):
        raise ValueError('incomplete/overlapping Orin signed SPI graph')
    if not any(p['partition'] == 'BCT' for p in payloads):
        raise ValueError('generated BR-BCT missing')
    return {'sha256':hashlib.sha256(expected).hexdigest(), 'payloads':payloads,
            'index_sha256':hashlib.sha256(Path(index).read_bytes()).hexdigest()}, bytes(expected)


def qspi_geometry(transport):
    """Read-only mtd0 geometry from the RAM recovery (sysfs reads only)."""
    measured = {name: transport.shell('/bin/cat', '/sys/class/mtd/mtd0/' + name).decode().strip()
                for name in GEOMETRY_FIELDS}
    check_geometry(measured)
    return measured


def check_geometry(measured):
    for name, allowed in GEOMETRY:
        if measured.get(name) not in allowed:
            raise ValueError('unexpected Orin SPI geometry/type: ' + name + '=' + str(measured.get(name)) +
                             ' (accepted: ' + ', '.join(allowed) + ')')
    return measured


def vendor_functions(source):
    """Select exact vendor functions, not its disk-enumerating main program."""
    text = Path(source).read_text()
    selected = []
    for name in ('write_to_spi_partition', 'sha1_verify'):
        match = re.search(r'^function ' + name + r'\n\{\n.*?^\}', text, re.M | re.S)
        if not match:
            raise ValueError('pinned vendor SPI function unavailable')
        selected.append(match[0])
    return '\n'.join(selected)


def board_hashes(transport, directory):
    """SHA-256 of every 4 MiB /dev/mtd0 chunk, computed on the board.

    One fixed remote script: each chunk is read with mtd_debug into the
    validated private scratch directory and hashed there, so only ~16 short
    lines cross the link instead of 64 MiB.
    """
    chunk = directory + '/chunk.bin'
    offsets = list(range(0, CAPACITY, CHUNK))
    script = ('set -eu\nc=' + shlex.quote(chunk) + '\n'
              'for o in ' + ' '.join(map(str, offsets)) + '; do\n'
              '  /usr/sbin/mtd_debug read /dev/mtd0 "$o" ' + str(CHUNK) + ' "$c" >/dev/null\n'
              '  printf "%s " "$o"\n'
              '  /usr/bin/sha256sum "$c"\n'
              'done\n'
              '/bin/rm -f "$c"\n')
    output = transport.shell('/bin/bash', '-c', script, timeout=HASH_TIMEOUT).decode()
    hashes = []
    for offset, line in zip(offsets, output.splitlines()):
        match = re.fullmatch(r'([0-9]+) ([0-9a-f]{64})  ' + re.escape(chunk), line)
        if not match or int(match[1]) != offset:
            raise ValueError('unexpected board-side Orin SPI hash output')
        hashes.append((offset, match[2]))
    if len(hashes) != len(offsets) or len(output.splitlines()) != len(offsets):
        raise ValueError('incomplete board-side Orin SPI hash output')
    return hashes


def mismatched(hashes, expected):
    """Offsets of chunks whose board hash differs from the approved bytes."""
    return [offset for offset, digest in hashes
            if digest != hashlib.sha256(expected[offset:offset + CHUNK]).hexdigest()]


def hash_pass(transport, directory, expected, label):
    import time
    started = time.monotonic()
    print('QSPI: hashing all 64 MiB on the board (' + label + ')...', flush=True)
    result = mismatched(board_hashes(transport, directory), expected)
    print('QSPI: board-side hash pass done in %d:%02d' % divmod(int(time.monotonic() - started), 60), flush=True)
    return result


def provision(vendor, transport):
    index = vendor.qspi_signed / 'flash.idx'
    xml = vendor.qspi_signed / 'flash.xml.tmp'
    stock = vendor.tree / STOCK_XML
    contract, expected = plan(index, xml, stock, partition_guids(vendor.board, stock))
    if contract != vendor.orin_plan or hashlib.sha256(expected).hexdigest() != contract['sha256']:
        raise ValueError('Orin approved generated SPI bytes changed')
    transport.bind()
    from nvidia_flash_tools.transport import check_remote_ecid
    check_remote_ecid(transport, vendor.approved_identity['ecid'])
    # Validate the one MTD controller BEFORE erase; no eMMC/block operation.
    # Erase block size only has to divide the device: it is erased whole and
    # read back in full. Orin NX/Nano modules use 4 KiB-sector QSPI NOR (J4012).
    for name, allowed in GEOMETRY:
        actual = transport.shell('/bin/cat', '/sys/class/mtd/mtd0/' + name).decode().strip()
        if actual not in allowed:
            raise ValueError('unexpected Orin SPI geometry/type: ' + name + '=' + actual)
    directory = transport.shell('/bin/mktemp','-d','/tmp/admiral-spi-XXXXXXXX').decode().strip()
    if not re.fullmatch(r'/tmp/admiral-spi-[A-Za-z0-9]{8}', directory):
        raise ValueError('invalid SPI scratch directory')
    local = vendor.workspace.root / 'orin-spi-executor.sh'
    result = {'size':CAPACITY,'sha256':contract['sha256'],'generated_partitions':contract['payloads'],
              'verification':'board-sha256-4MiB-chunks'}
    try:
        # Every chunk already equal to the approved bytes: the whole 64 MiB is
        # identical, so erase + write would only rewrite the same bytes.
        if not hash_pass(transport, directory, expected, 'before erase'):
            print('QSPI: already identical to the approved image; erase and write skipped', flush=True)
            return dict(result, write='skipped-identical')
        for payload in contract['payloads']:
            target = directory + '/' + payload['filename']
            transport.push(index.parent / payload['filename'], target)
            if transport.shell('/usr/bin/sha256sum', target).decode().split() != [payload['sha256'], target]:
                raise ValueError('staged SPI firmware hash differs')
        functions = vendor_functions(vendor.tree/'tools/kernel_flash/l4t_flash_from_kernel.sh')
        # Vendor method receives only validated SPI rows and our private RAM graph.
        script = ('#!/bin/bash\nset -euo pipefail\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'
                  'log_debug() { :; }; log_warning() { :; }; log_error() { echo "$*" >&2; };\n' + functions + '\n' +
                  'COMMON_IMAGES_DIR=' + shlex.quote(directory) + '\nINTERNAL=.\n'
                  'ekb_sn=\ndevice_sn=\ntarget_partname=\n'
                  '/usr/sbin/flash_erase /dev/mtd0 0 0\n')
        for row in csv.reader(index.read_text().splitlines(), skipinitialspace=True):
            script += 'write_to_spi_partition ' + shlex.quote(', '.join(row)) + ' /dev/mtd0\n'
        script += 'sync\n'
        local.write_text(script); local.chmod(0o600)
        transport.push(local, directory + '/executor.sh')
        if transport.shell('/usr/bin/sha256sum',directory+'/executor.sh').decode().split() != [hashlib.sha256(local.read_bytes()).hexdigest(),directory+'/executor.sh']:
            raise ValueError('staged Orin SPI executor hash mismatch')
        # Rebind immediately before the first persistent write.
        transport.bind(); check_remote_ecid(transport, vendor.approved_identity['ecid'])
        # Whole-device NOR erase + write takes minutes (NVIDIA's own secureflash
        # wrote this J4012's QSPI in ~15 min); the 120 s command default killed it.
        import time
        started = time.monotonic()
        print('QSPI: erasing and writing 64 MiB on the board (no progress output from the NVIDIA writer)...', flush=True)
        transport.shell('/bin/bash', directory + '/executor.sh', timeout=EXECUTOR_TIMEOUT)
        print('QSPI: written in %d:%02d' % divmod(int(time.monotonic() - started), 60), flush=True)
        # All 16 chunk hashes equal => the device equals expected, whose sha256
        # is the approved contract hash checked above.
        bad = hash_pass(transport, directory, expected, 'verify')
        if bad:
            raise ValueError('full-controller Orin SPI readback mismatch at offset ' + str(bad[0]))
        return dict(result, write='written')
    finally:
        local.unlink(missing_ok=True)
        transport.shell('/bin/rm','-rf',directory)
