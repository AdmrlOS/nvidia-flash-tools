"""R39.2.1 Orin SPI-only signed-package and full-controller verification.

Matches l4t_flash_from_kernel.sh write_to_spi_partition, including 16KiB
BR-BCT repetition. This is NOT Thor's 256KiB BCT transformation.
"""
import csv
import hashlib
from pathlib import Path
import re
import shlex
from nvidia_flash_tools.vendor import qspi_package

CAPACITY = 64 * 1024 * 1024


def plan(index, xml, stock):
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
    if len(names) != len(set(names)) or set(names) != set(allowed):
        raise ValueError('Orin SPI layout must preserve exact stock partition names')
    root = Path(index).parent
    expected = bytearray(b'\xff' * CAPACITY)
    rows, seen, extents, payloads = [], set(), [], []
    for row in csv.reader(Path(index).read_text().splitlines(), skipinitialspace=True):
        if len(row) != 8 or not re.fullmatch(r'3:0:[A-Za-z0-9_-]+', row[1]):
            raise ValueError('unsupported Orin signed flash index')
        name = row[1].split(':')[2]
        if name not in names or name in seen or not all(re.fullmatch('[0-9]+', row[i]) for i in (0, 2, 3, 5)):
            raise ValueError('duplicate/unknown Orin partition or range')
        start, size, length = map(int, (row[2], row[3], row[5]))
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


def provision(vendor, transport):
    index = vendor.tree / 'bootloader/signed/flash.idx'
    xml = vendor.tree / 'bootloader/signed/flash.xml.tmp'
    stock = vendor.tree / 'bootloader/generic/cfg/flash_t234_qspi.xml'
    contract, expected = plan(index, xml, stock)
    if contract != vendor.orin_plan:
        raise ValueError('Orin approved generated SPI bytes changed')
    transport.bind()
    from nvidia_flash_tools.transport import check_remote_ecid
    check_remote_ecid(transport, vendor.approved_identity['ecid'])
    # Validate the one MTD controller BEFORE erase; no eMMC/block operation.
    for name, value in (('size',str(CAPACITY)), ('erasesize','65536'), ('type','nor')):
        actual = transport.shell('/bin/cat', '/sys/class/mtd/mtd0/' + name).decode().strip()
        if actual != value:
            raise ValueError('unexpected Orin SPI geometry/type')
    directory = transport.shell('/bin/mktemp','-d','/tmp/admiral-spi-XXXXXXXX').decode().strip()
    if not re.fullmatch(r'/tmp/admiral-spi-[A-Za-z0-9]{8}', directory):
        raise ValueError('invalid SPI scratch directory')
    local = vendor.workspace.root / 'orin-spi-executor.sh'
    try:
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
        transport.shell('/bin/bash', directory + '/executor.sh')
        digester = hashlib.sha256()
        for offset in range(0, CAPACITY, 4 * 1024 * 1024):
            count = min(4 * 1024 * 1024, CAPACITY-offset)
            target = directory + '/readback.bin'
            transport.shell('/usr/sbin/mtd_debug', 'read', '/dev/mtd0', str(offset), str(count), target)
            data = transport.shell('/bin/cat', target)
            if data != expected[offset:offset+count]:
                raise ValueError('full-controller Orin SPI readback mismatch at ' + str(offset))
            digester.update(data)
        if digester.hexdigest() != contract['sha256']:
            raise ValueError('Orin SPI readback hash mismatch')
        return {'size':CAPACITY,'sha256':digester.hexdigest(),'generated_partitions':contract['payloads']}
    finally:
        local.unlink(missing_ok=True)
        transport.shell('/bin/rm','-rf',directory)
