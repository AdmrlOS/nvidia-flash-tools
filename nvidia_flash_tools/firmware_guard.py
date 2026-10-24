"""Installed only into authenticated pinned vendor code, before approval.

Preflight the actual NVIDIA FlashUsingADB method with file-only boundaries.
No ADB call is possible until every transformed send matches the approved plan.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import FunctionType, SimpleNamespace


def install(cls, index, approved, chain, scratch=None):
    original = cls.FlashUsingADB
    scratch_root = str(Path(scratch or tempfile.gettempdir()).resolve())
    def checked(self, filename, updates, directory, queue):
        cfg=self.targetConfig
        flags=cfg.parsed_commandline
        if (not cfg.is_l4t or cfg.n_Asymmetric or cfg.headers or cfg.BOOTBURN_PYTEST or
                cfg.n_FlashHypervisor or cfg.n_FlashLinux is not True or updates or
                getattr(cfg, 's_BrickOnCoreFWFlashFail', False) or
                cfg.s_L4TBootChainSelect != chain or any(flags.get(k) for k in ('s','o','O','m','clean'))):
            raise ValueError('unsupported vendor firmware transformation configuration before erase')
        if Path(filename).resolve() != Path(index).resolve():
            raise ValueError('vendor firmware index differs from approved plan')
        seen=[]
        def check(part):
            key=(part.LinuxPartitionName,part.PartitionName,int(part.Start),int(part.Size))
            expected=approved.get(part.PartitionName)
            data=Path(part.FileName).read_bytes()
            if (expected is None or list(key) != expected['key'] or len(data) != expected['size'] or
                    hashlib.sha256(data).hexdigest() != expected['sha256']):
                raise ValueError('vendor transformed bytes differ from approved firmware plan')
            seen.append(part.PartitionName)
            return 0
        class Files:
            def catFile(self,path): return Path(path).read_text()
            def removeFile(self,path): Path(path).unlink(missing_ok=True)
            def Copy(self,source,target): shutil.copyfile(source,target)
        dry=copy.copy(self)
        dry.shellUtils=Files()
        dry.SendFileUsingADB=lambda part,*a:check(part)
        dry.EraseQspi=lambda *a:None
        dry.AdbShell=lambda *a: (_ for _ in ()).throw(ValueError('unexpected ADB during firmware preflight'))
        dry.AdbPush=dry.AdbShell
        # Plain filenames in FileToFlash are relative to its flash-images dir.
        # Copy only authenticated files, never invent board/SKU/EEPROM metadata.
        cwd=os.getcwd()
        filename=str(Path(filename).resolve())
        directory=Path(directory).resolve()
        scratch=Path(scratch_root)
        if scratch == directory or directory in scratch.parents:
            raise ValueError('firmware scratch must be outside immutable package')
        def populate(target):
            for entry in directory.iterdir():
                if entry.is_file(): shutil.copyfile(entry,Path(target)/entry.name)
        with tempfile.TemporaryDirectory(prefix='firmware-plan-',dir=scratch) as tmp:
            populate(tmp)
            try: original(dry,filename,updates,tmp,None)
            finally: os.chdir(cwd)
        if sorted(seen) != sorted(approved):
            raise ValueError('vendor firmware preflight missing or duplicate programmed ranges')
        # Retain production inputs/outputs as evidence outside the approved tree.
        work=Path(tempfile.mkdtemp(prefix='firmware-execution-',dir=scratch))
        populate(work)
        # The pinned PT helper uses NamedTemporaryFile without a directory.
        pt_helper=self.dup_pt_to_fill_partition
        pt_globals=dict(pt_helper.__func__.__globals__)
        pt_globals['tempfile']=SimpleNamespace(NamedTemporaryFile=lambda **kw:
            tempfile.NamedTemporaryFile(dir=work,**kw))
        self.dup_pt_to_fill_partition=FunctionType(pt_helper.__func__.__code__,pt_globals).__get__(self)
        def hashes():
            result={}
            for path in work.iterdir():
                info=path.lstat()
                if path.is_symlink() or not path.is_file() or info.st_nlink != 1:
                    raise ValueError('unexpected firmware scratch entry')
                result[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
            return result
        expected=hashes()
        sender=self.SendFileUsingADB
        seen.clear()
        def guarded(part,*args):
            check(part)
            output=Path(part.FileName).resolve()
            if output.parent != work:
                raise ValueError('vendor transformed output outside execution scratch')
            pin=approved[part.PartitionName]['sha256']
            if output.name in expected and expected[output.name] != pin:
                raise ValueError('vendor changed immutable firmware input')
            expected[output.name]=pin
            return sender(part,*args)
        self.SendFileUsingADB=guarded
        try:
            result=original(self,filename,updates,str(work),queue)
            if sorted(seen) != sorted(approved) or hashes() != expected:
                raise ValueError('firmware scratch changed after transformed send')
            with (work.parent/(work.name+'.json')).open('x') as evidence:
                json.dump({'files':expected,'approved':approved},evidence,sort_keys=True)
            return result
        finally:
            self.SendFileUsingADB=sender
            self.dup_pt_to_fill_partition=pt_helper
            os.chdir(cwd)
    cls.FlashUsingADB=checked
