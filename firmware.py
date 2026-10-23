"""Pinned R39.2.1 programmed-byte planning and independent readback.

bootburn_adb.py SHA256 d36a93594b1af040ce3c2f6f1aade0fe0eff8a61fc42fadf3847b22d2440c023:
111-116 FF padding; 994-1005 PT floor-copy expansion; 1155-1206 L4T
BCT three 256KiB blocks; 1208-1254 bad-page block replication;
1366-1388 complete SPI erase; 1432-1445 nvdd read API.
Plans describe the entire 64MiB controller, not only input-file prefixes.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
import tempfile
from vendor import thor_flash_graph

CAPACITY = 64 * 1024 * 1024
BLOCK = 262144

@dataclass(frozen=True)
class ProgrammedRange:
    partition: str
    device: str
    offset: int
    data: bytes

@dataclass(frozen=True)
class ProgrammedPlan:
    ranges: tuple
    programmed: tuple
    sha256: str
    chain: str


def plan_qspi(index, *, chain='A'):
    if chain not in ('A', 'B'):
        raise ValueError('unsupported BCT boot-chain semantics')
    rows = thor_flash_graph(index)
    programmed = []
    for row in rows:
        device, name, filename, start, size, blocks, resize, sku, bch, header, md5, rw = row
        start, size = int(start), int(size)
        # These are static signature metadata, not runtime transformations:
        # parseFileToFlashEntry:135-136 assigns them; FlashUsingADB never
        # consumes them. Re-signing is not requested by the fixed command.
        if (not re.fullmatch(r'[A-Za-z0-9_-]+', bch) or
                header not in ('0', '8', '9', '12') or 'ist' in name):
            raise ValueError('unsupported BCH/header/skipped-IST firmware semantics')
        raw = (Path(index).parent / filename).read_bytes()
        if not raw:
            raise ValueError('empty firmware payload has no programmed plan')
        if raw[:4] == b'\x3a\xff\x26\xed':
            raise ValueError('unsupported sparse firmware semantics')
        if name == 'pt':
            raw = raw * (size // len(raw))
        elif name == 'bct':
            if len(raw) >= 16384 or size < BLOCK * 3:
                raise ValueError('unsupported legacy L4T BCT size')
            block = raw + b'\xff' * (BLOCK-len(raw))
            raw = (b'\xff'*BLOCK if chain == 'B' else block) + block * 2
        elif name == 'bad-page':
            if len(raw) >= BLOCK or size % BLOCK:
                raise ValueError('unsupported bad-page block expansion')
            raw = (raw + b'\xff' * (BLOCK-len(raw))) * (size // BLOCK)
        if not raw or len(raw) > size:
            raise ValueError('unsupported expanded firmware extent')
        programmed.append(ProgrammedRange(name, device, start, raw))
    ranges=[];end=0
    for part in sorted(programmed, key=lambda p:p.offset):
        if part.offset < end:
            raise ValueError('overlapping transformed programmed ranges')
        if part.offset > end:
            ranges.append(ProgrammedRange('erased-gap',part.device,end,b'\xff'*(part.offset-end)))
        ranges.append(part);end=part.offset+len(part.data)
    if end < CAPACITY:
        ranges.append(ProgrammedRange('erased-gap',programmed[0].device,end,b'\xff'*(CAPACITY-end)))
    contract=[{'partition':p.partition,'device':p.device,'offset':p.offset,'size':len(p.data),
               'sha256':hashlib.sha256(p.data).hexdigest()} for p in ranges]
    pin=hashlib.sha256(json.dumps({'chain':chain,'ranges':contract},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return ProgrammedPlan(tuple(ranges),tuple(programmed),pin,chain)


def verify_qspi(client, serial, index, scratch, *, plan=None):
    plan = plan or plan_qspi(index)
    if plan_qspi(index,chain=plan.chain) != plan:
        raise ValueError('approved firmware plan changed')
    result=[]
    with tempfile.TemporaryDirectory(prefix='firmware-readback-',dir=scratch) as tmp:
        for i,part in enumerate(plan.ranges):
            digest=hashlib.sha256()
            for chunk,offset in enumerate(range(0,len(part.data),4*1024*1024)):
                expected=part.data[offset:offset+4*1024*1024]
                remote='/tmp/admiral-readback-%d-%d.bin'%(i,chunk)
                local=Path(tmp)/('readback-%d-%d.bin'%(i,chunk))
                command=('/tmp/wr_sh.sh /tmp/nvdd --device %s --partsize %d --startoffset %d --outputbin %s'
                         %(part.device,len(expected),part.offset+offset,remote))
                output=client.shell(serial,command)
                if output.split().count(b'EXITCODE=0') != 1 or any(w.startswith(b'EXITCODE=') and w != b'EXITCODE=0' for w in output.split()):
                    raise ValueError('firmware read command failed/missing wrapper exit status')
                client.pull(serial,remote,local)
                actual=local.read_bytes()
                if actual != expected: raise ValueError('firmware readback mismatch: '+part.partition)
                digest.update(actual);local.unlink();client.shell(serial,'/bin/rm -f '+remote)
            result.append({'partition':part.partition,'device':part.device,'offset':part.offset,
                           'size':len(part.data),'sha256':digest.hexdigest(),'plan_sha256':plan.sha256})
    return result


def bind_programmed_plan(vendor, index):
    """Pin actual vendor transformation implementation and preflight before erase."""
    source=vendor.tree/'unified_flash/out/bsp_images/tools/flashtools/bootburn_t264_py/bootburn_adb.py'
    if hashlib.sha256(source.read_bytes()).hexdigest() != 'd36a93594b1af040ce3c2f6f1aade0fe0eff8a61fc42fadf3847b22d2440c023':
        raise ValueError('unsupported NVIDIA firmware transformation source')
    plan=plan_qspi(index)
    # The exact fixed command selects L4T/A, no headers/asymmetric/sparse flags.
    # Runtime configuration and production transformed sends are checked again.
    rows={r[1]:r for r in thor_flash_graph(index)}
    approved={p.partition:{'key':[p.device,p.partition,p.offset,int(rows[p.partition][4])],
                           'size':len(p.data),'sha256':hashlib.sha256(p.data).hexdigest()}
              for p in plan.programmed}
    if any(len(Path(r[2]).parts)!=1 for r in rows.values()):
        raise ValueError('unsupported nested vendor firmware reference')
    guard=Path(__file__).with_name('firmware_guard.py').read_text()
    # Inline installer-owned guard in this authenticated generated module. Its
    # whole bytes and constants enter package_hashes/approval, no extra imports.
    scratch=vendor.workspace.root if vendor.workspace is not None else vendor.tree.parent
    source.write_text(source.read_text()+'\n'+guard+'\ninstall(bootburn_adb, '+repr(str(Path(index).resolve()))+', '+repr(approved)+", 'A', "+repr(str(scratch))+')\n# approved full-controller plan SHA256: '+plan.sha256+'\n')
    vendor.firmware_plan=plan
    if vendor.workspace is not None:
        from workspace import snapshot
        vendor.workspace.expected=snapshot(vendor.tree,vendor.workspace.owner)
        vendor.workspace.record('programmed-firmware-plan')
    return plan
