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

FILES = tuple(sorted(("LICENSE OPENSSL-LICENSE.txt MUSL-COPYRIGHT.txt test_support.py test_firsttest.py README.md install.py image.py recovery-write.sh release.json "
    "test_installer.py test_integration.py transport.py vendor.py writer.py flow.py "
    "fingerprint.py package.py security.py test_security.py "
    "recovery-io.c test_recovery_io.c workspace.py native_session.py "
    "test_execution.py test_native_session.c NATIVE-PROTOCOL.md adb_socket.py "
    "test_binary_transport.py native_pipe_fixture.c firmware.py firmware_guard.py test_firmware.py download.py test_download.py test_namespace.py native_namespace_fixture.c test_adb_v2.py thor.py test_guided.py orin.py orin_firmware.py orin_recovery.py orin_payload.py test_orin_payload.py test_orin_probe.py test_orin_flow.py test_orin_oracle.py test_orin_signed_cfg.py orin_native_fixture.c test_orin.py").split()))

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
