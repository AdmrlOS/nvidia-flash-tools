#!/usr/bin/env python3
"""Reproducible source bundle with a static recovery helper; not release authorization."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

FILES = tuple(sorted(("LICENSE OPENSSL-LICENSE.txt MUSL-COPYRIGHT.txt README.md install.py "
    "recovery-write.sh release.json package.py recovery-io.c test_recovery_io.c "
    "test_native_session.c NATIVE-PROTOCOL.md native_pipe_fixture.c "
    "native_namespace_fixture.c thor.py orin.py orin_native_fixture.c "
    "docs/reference.md docs/development.md docs/troubleshooting.md").split() +
    ['vendor-inputs/recomputer-j40/' + name for name in (
        'README.md', 'recomputer-j40-qspi.conf', 'recomputer-j40-recovery.conf', 'sample-rootfs-members.txt',
        'patches/0001-mb2-bct-skip-carrier-eeprom-read.patch',
        'dtb/tegra234-j401-p3768-0000+p3767-0000-recomputer.dtb',
        'dtb/tegra234-j401-p3768-0000+p3767-0001-recomputer.dtb',
        'dtb/tegra234-j401-p3768-0000+p3767-0003-recomputer.dtb',
        'dtb/tegra234-j401-p3768-0000+p3767-0004-recomputer.dtb',
        'dtbo/tegra234-p3767-camera-p3768-imx219-dual-seeed.dtbo')] +
    ['vendor-inputs/mic-733-ao/' + name for name in (
        'README.md', 'mic-733-ao-qspi.conf', 'mic-733-ao-recovery.conf', 'sample-rootfs-members.txt',
        'bct/tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts',
        'patches/0001-mb1-pinmux-gpio-mic-733-ao.patch',
        'dtb/tegra234-mic-733-ao+p3701-0000.dtb',
        'dtb/tegra234-mic-733-ao+p3701-0004.dtb',
        'dtb/tegra234-mic-733-ao+p3701-0005.dtb')] +
    ['nvidia_flash_tools/' + name + '.py' for name in (
        '__init__', 'adb_socket', 'download', 'fingerprint', 'firmware', 'firmware_guard',
        'carrier', 'flow', 'image', 'install', 'native_session', 'orin', 'orin_firmware', 'orin_payload',
        'orin_recovery', 'security', 'thor', 'transport', 'vendor', 'vendor_inputs', 'workspace', 'writer')] +
    ['tests/' + name + '.py' for name in (
        '__init__', 'test_support', 'test_firsttest', 'test_installer', 'test_integration',
        'test_security', 'test_execution', 'test_binary_transport', 'test_firmware',
        'test_download', 'test_namespace', 'test_adb_v2', 'test_guided', 'test_orin_payload',
        'test_orin_probe', 'test_orin_flow', 'test_orin_oracle', 'test_orin_signed_cfg',
        'test_orin', 'test_orin_j40', 'test_orin_mic733', 'test_layout')]))

def sha(data):
    return hashlib.sha256(data).hexdigest()

def build(output, compiler):
    root = Path(__file__).resolve().parent
    binary = output.with_name(output.name + '.helper')
    command = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror', '-static',
               '-Wl,--build-id=none', '-ffile-prefix-map=' + str(root) + '=.',
               str(root / 'recovery-io.c'), '-lcrypto', '-pthread', '-ldl', '-o', str(binary)]
    if binary.exists(): raise ValueError('helper output already exists')
    subprocess.run(command, check=True)
    helper = binary.read_bytes()
    # ELF64 little-endian EM_AARCH64, no PT_INTERP (static). Check actual bytes.
    import struct
    if helper[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', helper, 18)[0] != 183:
        raise ValueError('expected aarch64 ELF helper')
    off = struct.unpack_from('<Q', helper, 32)[0]
    size, count = struct.unpack_from('<HH', helper, 54)
    if any(struct.unpack_from('<I', helper, off+i*size)[0] == 3 for i in range(count)):
        raise ValueError('dynamic interpreter forbidden')
    entries = {}
    for filename in FILES:
        path = root / filename
        if not path.is_file() or path.is_symlink(): raise ValueError('regular allowlisted sources required')
        entries[filename] = path.read_bytes()
    source_hash = sha(entries['recovery-io.c'])
    manifest = {'schema':1, 'classification':'engineering-candidate', 'hardware_qualified':False,
                'authorization':None, 'artifacts':{k:{'sha256':sha(v),'size':len(v)} for k,v in entries.items()},
                'recovery':{'helper':{'path':'recovery-io','sha256':sha(helper),
                    'source_sha256':source_hash, 'source_hash':source_hash, 'size':len(helper),
                    'architecture':'aarch64', 'static':True}},
                'build':{'compiler_sha256':sha(Path(compiler).read_bytes()),
                         'compiler_version':subprocess.check_output([str(compiler),'--version'],text=True).splitlines()[0],
                         'flags':command[1:6]}}
    engineering_release = json.loads(entries['release.json'])
    engineering_release['recovery'] = manifest['recovery']
    engineering_release['engineering_provenance'] = {'authorization':None, 'generated':True}
    entries['engineering-release.json'] = (json.dumps(engineering_release,sort_keys=True,indent=2)+'\n').encode()
    entries['recovery-io'] = helper
    manifest['engineering_release_sha256'] = sha(entries['engineering-release.json'])
    entries['engineering-manifest.json'] = (json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    with output.open('xb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as gz:
        with tarfile.open(fileobj=gz,mode='w') as archive:
            for name, data in sorted(entries.items()):
                info = tarfile.TarInfo('admiral-jetson-installer/' + name)
                info.size=len(data); info.mode=0o755 if name=='recovery-io' else 0o644
                archive.addfile(info,io.BytesIO(data))
    digest = sha(output.read_bytes())
    output.with_name(output.name+'.sha256').write_text(digest+'  '+output.name+'\n')
    print(digest,output.stat().st_size,output)
    return manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--compiler',type=Path,required=True)
    args=parser.parse_args()
    build(args.output,args.compiler)

if __name__=='__main__':main()
