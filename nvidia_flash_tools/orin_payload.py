"""Validate the exact T234 generated blob before allowing any RAM downloads."""
import gzip
import hashlib
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as ET


def hostkey(boot, *, require_tools=False):
    data = Path(boot).read_bytes()
    if data[:8] != b'ANDROID!' or len(data) < 608:
        raise ValueError('invalid selected Android recovery boot image')
    kernel, _, length, _, _, _, _, page = struct.unpack_from('<8I', data, 8)
    if page not in (2048,4096) or not kernel or not length:
        raise ValueError('invalid recovery boot geometry')
    offset = page + ((kernel+page-1)//page)*page
    if offset+length > len(data):
        raise ValueError('truncated selected recovery ramdisk')
    raw = gzip.decompress(data[offset:offset+length])
    position = 0; keys = {}; hardlinks = {}
    while position+110 <= len(raw):
        header = raw[position:position+110]
        if header[:6] != b'070701':
            raise ValueError('unsupported recovery cpio')
        fields = [int(header[i:i+8],16) for i in range(6,110,8)]
        size, namesize = fields[6],fields[11]
        name = raw[position+110:position+110+namesize-1].decode()
        start = (position+110+namesize+3)&~3
        end = start+size
        if end > len(raw): raise ValueError('truncated recovery cpio')
        if name == 'TRAILER!!!': break
        name = name.removeprefix('./')
        if name in keys: raise ValueError('duplicate recovery cpio member')
        keys[name] = raw[start:end]
        if fields[4] > 1 and fields[1] & 0o170000 == 0o100000:
            hardlinks.setdefault((fields[0],fields[7],fields[8]),[]).append(name)
        position = (end+3)&~3
    # GNU cpio stores a multiply-linked inode's bytes in only one member.
    for names in hardlinks.values():
        contents = [keys[name] for name in names if keys[name]]
        if contents and any(item != contents[0] for item in contents):
            raise ValueError('ambiguous recovery hardlink contents')
        if contents:
            for name in names: keys[name] = contents[0]
    # Ubuntu's merged-/usr initrd may encode /bin as a directory symlink.
    for prefix,target in (('bin','usr/bin'),('sbin','usr/sbin')):
        if keys.get(prefix) in (target.encode(),('../'+target).encode(),('/'+target).encode()):
            for name,value in list(keys.items()):
                if name.startswith(target+'/'): keys[prefix+name[len(target):]] = value
    if require_tools:
        required = ['usr/sbin/mtd_debug','usr/sbin/flash_erase','usr/bin/sha256sum',
                    'bin/sha1sum','bin/cut','bin/sed','bin/sync','bin/bash',
                    'bin/nv_fuse_read.sh','bin/cat','bin/chmod','bin/mktemp','bin/rm']
        missing = [name for name in required if not keys.get(name)]
        if missing:
            raise ValueError('FINAL recovery initrd missing execution utility: '+', '.join(missing))
        config = keys.get('initrd_flash.cfg',b'').decode()
        if any(line.strip().split('=')[0] in ('erase_all','erase_qspi','boot_rootfs','nfsnet','adb')
               for line in config.splitlines() if line.strip() and not line.startswith('#')):
            raise ValueError('FINAL recovery initrd enables unapproved automatic action')
    public = keys.get('etc/ssh/ssh_host_ed25519_key.pub',b'').decode().split()
    if len(public) < 2 or public[0] != 'ssh-ed25519':
        raise ValueError('missing host key in FINAL recovery initrd')
    # Public and private key must agree; sshd authenticates with the private key.
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory)/'key'
        key.write_bytes(keys.get('etc/ssh/ssh_host_ed25519_key',b'')); key.chmod(0o600)
        derived = subprocess.check_output(['/usr/bin/ssh-keygen','-y','-f',str(key)]).decode().split()
    if derived[:2] != public[:2]: raise ValueError('final recovery key pair differs')
    return public[:2]


def validate_blob(directory, expected_boot, expected_key, chip_major=None):
    directory = Path(directory)
    raw = (directory/'blob.xml').read_bytes()
    if len(raw) > 4*1024*1024 or b'<!DOCTYPE' in raw or b'<!ENTITY' in raw:
        raise ValueError('unsupported generated blob XML')
    root = ET.fromstring(raw)
    entries = root.findall('file')
    kernels = [e for e in entries if e.get('type') == 'kernel']
    if len(kernels) != 1: raise ValueError('blob must contain exactly one selected kernel')
    for entry in entries:
        name = entry.get('name','')
        if Path(name).name != name or not name or not (directory/name).is_file():
            raise ValueError('invalid generated blob member')
    kernel = directory/kernels[0].get('name')
    if kernel.read_bytes() != Path(expected_boot).read_bytes():
        raise ValueError('actual generated blob kernel differs from approved recovery')
    if hostkey(kernel) != expected_key:
        raise ValueError('host key differs in actual generated RAM payload')
    # Regenerate with the actual pinned tegrahost serializer, not a byte search
    # or an invented parser for NVIDIA's binary blob table.
    oracle = directory/'admiral-blob-oracle.bin'
    oracle.unlink(missing_ok=True)
    chip = ['--chip','0x23'] + ([] if chip_major is None else [chip_major])
    subprocess.run([str(directory/'tegrahost_v2'),*chip,'--generateblob',
                    'blob.xml',oracle.name],cwd=directory,check=True,stdout=subprocess.PIPE)
    try:
        actual = (directory/'blob.bin').read_bytes()
        expected = oracle.read_bytes()
        # tegrahost_v2 fills header bytes 8..75 from a per-second seed (observed
        # R39.2.1: identical inputs differ only there, across file counts, sizes
        # and chip majors). Everything else must be byte-identical.
        salt = slice(8, 76)
        if (len(actual) != len(expected) or actual[:4] != b'blob'
                or actual[:salt.start] + actual[salt.stop:] != expected[:salt.start] + expected[salt.stop:]):
            raise ValueError('generated RCM blob bytes differ from exact manifest')
        return hashlib.sha256(actual).hexdigest()
    finally:
        oracle.unlink(missing_ok=True)


def selected_executor(argv, directory, expected_boot, expected_key, expected_uid):
    """Run real vendor signing/generation first, defer only its USB sends."""
    import os
    import runpy
    import sys
    os.chdir(directory)
    sys.path.insert(0,str(directory))
    import tegraflash_impl_t234 as implementation
    original = implementation.run_command
    pending = []
    def capture(command, *args, **kwargs):
        name = Path(command[0]).name
        if name in ('tegrarcm_v2','tegradevflash_v2'):
            if name != 'tegrarcm_v2' or '--download' not in command:
                raise ValueError('unapproved device command during RAM generation')
            pending.append((list(command),args,kwargs))
            return ''
        return original(command,*args,**kwargs)
    implementation.run_command = capture
    # Retain the vendor's own generation directory for validation and sends.
    sys.argv = argv + ['--keep']
    runpy.run_path(str(Path(directory)/'tegraflash.py'),run_name='__main__')
    from tegraflash_internal import paths, values
    generated = Path(paths['TMP'])
    # Serializer is authenticated in bootloader; generated files are held in TMP.
    os.chdir(generated)
    if not (generated/'tegrahost_v2').exists():
        raise ValueError('missing pinned serializer in generated graph')
    pin = validate_blob(generated,expected_boot,expected_key,values.get('--chip_major'))
    if len(pending) != 2 or pending[-1][0][-3:] != ['--download','blob','blob.bin']:
        raise ValueError('unexpected selected T234 RAM download sequence')
    selected_port = argv[argv.index('--instance')+1]
    if any(command.count('--instance') != 1 or command[command.index('--instance')+1] != selected_port
           for command,_,_ in pending):
        raise ValueError('RAM download escaped selected USB instance')
    # Generation may take minutes: re-identify immediately before first send.
    import re
    usb = Path('/sys/bus/usb/devices')
    devices = [p.name for p in usb.iterdir() if (p/'idVendor').exists()
               and (p/'idVendor').read_text().strip() == '0955']
    if devices != [selected_port]: raise ValueError('USB set changed before RAM download')
    observed = subprocess.check_output([str(Path(directory)/'tegrarcm_v2'),'--new_session',
                                       '--chip','0x23','--instance',selected_port,'--uid'])
    identifiers = re.findall(rb'BR_CID: (0x[0-9a-fA-F]{32})',observed)
    if identifiers != [expected_uid.encode()]: raise ValueError('silicon changed before RAM download')
    for command,args,kwargs in pending:
        original(command,*args,**kwargs)
    print('ADMIRAL_VALIDATED_RCM_BLOB_SHA256='+pin)


if __name__ == '__main__':
    import json
    import sys
    selected_executor(json.loads(sys.argv[4]),Path(sys.argv[1]),Path(sys.argv[2]),json.loads(sys.argv[3]),sys.argv[5])
