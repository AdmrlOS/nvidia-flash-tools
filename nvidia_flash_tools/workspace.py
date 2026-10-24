"""Fresh authenticated extraction and held per-install execution authority.

The disk manifest is audit output, never an authorization token. Authority is a
live object holding flock and an in-memory complete filesystem snapshot.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import posixpath
import subprocess
import tarfile
from nvidia_flash_tools.security import ENV, trusted_directory


def snapshot(root, owner=0):
    root = Path(root)
    result = {}
    for p in sorted(root.rglob('*')):
        s = p.lstat()
        if s.st_uid != owner or (not stat.S_ISLNK(s.st_mode) and s.st_mode & 0o022):
            raise ValueError('untrusted workspace ownership/mode: ' + str(p))
        key = str(p.relative_to(root))
        if stat.S_ISREG(s.st_mode):
            if s.st_nlink != 1:
                raise ValueError('workspace hardlink refused')
            with p.open('rb') as f:
                digest = hashlib.file_digest(f, 'sha256').hexdigest()
            result[key] = ['file', stat.S_IMODE(s.st_mode), s.st_size, digest]
        elif stat.S_ISDIR(s.st_mode):
            result[key] = ['dir', stat.S_IMODE(s.st_mode)]
        elif stat.S_ISLNK(s.st_mode):
            # Sample-rootfs absolute links refer to its target root, not host /.
            target = os.readlink(p)
            boundary = root / 'rootfs' if 'rootfs' in p.relative_to(root).parts[:1] else root
            resolved = (boundary / target.lstrip('/') if target.startswith('/') else p.parent / target).resolve()
            if resolved != boundary and boundary not in resolved.parents:
                raise ValueError('workspace symlink escapes trust domain')
            result[key] = ['link', target]
        else:
            raise ValueError('workspace special file refused')
    return result


class Workspace:
    def __init__(self, destination, *, owner=0, runner=subprocess.run):
        if os.geteuid() != owner:
            raise ValueError('workspace requires expected effective owner')
        self.root = Path(destination).absolute()
        self.parent_fd = trusted_directory(self.root.parent, owner=owner)
        os.mkdir(self.root.name, 0o700, dir_fd=self.parent_fd)
        self.fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
        self.lock = os.open('session.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owner, self.runner = owner, runner
        self.tree = self.root / 'Linux_for_Tegra'
        self.expected = None
        self.inputs = {}
        self.closed = False
        self.controls = {}

    def authenticate_helper(self, source, record):
        """Copy once from an untrusted caller path; retain the release pin."""
        self.validate()
        target = self.root / 'approved-recovery-io'
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise ValueError('helper must be bounded regular file')
            with os.fdopen(fd, 'rb', closefd=False) as inp, target.open('xb') as out:
                count = 0
                while block := inp.read(1024 * 1024):
                    count += len(block)
                    if count > 16 * 1024 * 1024:
                        raise ValueError('helper grew beyond bound')
                    out.write(block)
        finally:
            os.close(fd)
        target.chmod(0o700)
        if hashlib.sha256(target.read_bytes()).hexdigest() != record['sha256']:
            target.unlink()
            raise ValueError('helper binary not authenticated by release')
        if 'size' in record and target.stat().st_size != record['size']:
            target.unlink()
            raise ValueError('helper size differs from release')
        self.controls[target.name] = record['sha256']
        self.validate()
        return target

    def _archive(self, source, record, name, destination):
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        copy = self.root / name
        with os.fdopen(fd, 'rb') as inp, copy.open('xb') as out:
            if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
                raise ValueError('archive must be regular')
            h, count = hashlib.sha256(), 0
            while data := inp.read(1024 * 1024):
                count += len(data)
                if count > record['size']:
                    raise ValueError('archive oversized')
                h.update(data)
                out.write(data)
            if count != record['size'] or h.hexdigest() != record['sha256']:
                raise ValueError('archive authentication failed')
        # Extract only authenticated private bytes. The data filter rejects
        # traversal, external links, device nodes and unsafe permission bits.
        with tarfile.open(copy) as archive:
            seen = set()
            def authenticated_filter(member, target):
                normalized = posixpath.normpath(member.name)
                if normalized in seen and not member.isdir():
                    raise ValueError('duplicate archive member')
                seen.add(normalized)
                # Absolute target-root links in Ubuntu refer to target /, not
                # the host. Materialize equivalent relative links so all host
                # preparation traversals remain inside the private rootfs.
                if member.issym() and member.linkname.startswith('/'):
                    if name != 'rootfs.tar':
                        raise ValueError('absolute BSP symlink refused')
                    link = posixpath.normpath(member.linkname).lstrip('/')
                    member = member.replace(linkname=posixpath.relpath(link, posixpath.dirname(normalized) or '.'))
                return tarfile.data_filter(member, target)
            archive.extractall(destination, filter=authenticated_filter)
        # Authenticated tar hardlinks are common in Ubuntu. Convert to independent
        # files before execution so later manifests have one inode per member.
        for p in Path(destination).rglob('*'):
            info = p.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                temporary = p.with_name(p.name + '.unlinked-' + os.urandom(8).hex())
                with p.open('rb') as inp, temporary.open('xb') as out:
                    import shutil
                    shutil.copyfileobj(inp, out)
                os.chmod(temporary, stat.S_IMODE(info.st_mode) & ~0o022)
                os.replace(temporary, p)
        copy.unlink()
        self.inputs[name] = dict(record)

    def prepare(self, bsp, rootfs, records):
        self._archive(bsp, records['archive'], 'bsp.tar', self.root)
        if not self.tree.is_dir() or self.tree.is_symlink():
            raise ValueError('missing vendor tree')
        target = self.tree / 'rootfs'
        target.mkdir(exist_ok=True)
        self._archive(rootfs, records['sample_rootfs'], 'rootfs.tar', target)
        self._prepare_compressor()
        self._seal_modes()
        self.expected = snapshot(self.tree, self.owner)
        self.run(['./apply_binaries.sh', '--rootless', '--target-overlay'])
        self.record('prepared')
        return self

    def _prepare_compressor(self):
        # Pinned vendor uses only standard bzip2 CLI via tar -I; parallel
        # decompression is optional. No dependency installation or PATH shim.
        import shutil
        if shutil.which('lbzip2', path=ENV['PATH']):
            return
        if not Path('/usr/bin/bzip2').is_file():
            raise ValueError('preparation requires lbzip2 or /usr/bin/bzip2')
        script = self.tree / 'apply_binaries.sh'
        text = script.read_text()
        count = text.count('-I lbzip2')
        if count != 2:
            raise ValueError('pinned apply_binaries compressor sites changed')
        script.write_text(text.replace('-I lbzip2', '-I /usr/bin/bzip2'))
        self.inputs['compressor_adapter'] = {'from':'-I lbzip2',
            'to':'-I /usr/bin/bzip2', 'sites':2,
            'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest()}

    def _normalize_generated_rootfs_links(self):
        # apply_binaries overlays reintroduce target-absolute links. Convert all
        # of them before resolving chains, then snapshot rejects actual escapes.
        root = self.tree / 'rootfs'
        for p in root.rglob('*'):
            if p.is_symlink():
                target = os.readlink(p)
                if target.startswith('/'):
                    replacement = os.path.relpath(root / target.lstrip('/'), p.parent)
                    p.unlink()
                    p.symlink_to(replacement)

    def _seal_modes(self):
        for p in self.tree.rglob('*'):
            if not p.is_symlink():
                os.chmod(p, p.stat().st_mode & ~0o022)

    def validate(self):
        if self.closed or self.expected is None:
            raise ValueError('workspace is not prepared/locked')
        check = trusted_directory(self.root, owner=self.owner)
        try:
            if os.fstat(check).st_ino != os.fstat(self.fd).st_ino:
                raise ValueError('workspace ancestor changed')
        finally:
            os.close(check)
        s, t = os.fstat(self.fd), self.root.lstat()
        if (s.st_dev, s.st_ino) != (t.st_dev, t.st_ino) or t.st_uid != self.owner or t.st_mode & 0o077:
            raise ValueError('workspace path replaced')
        for name, expected in self.controls.items():
            p = self.root / name
            info = p.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner or info.st_mode & 0o022 or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
                raise ValueError('session control artifact changed')
        if snapshot(self.tree, self.owner) != self.expected:
            raise ValueError('workspace tree changed, including imports or extra files')

    def run(self, argv, env=None, cwd=None, timeout=1800):
        self.validate()
        cwd = Path(cwd or self.tree).absolute()
        if cwd != self.tree and self.tree not in cwd.parents:
            raise ValueError('vendor cwd outside workspace')
        # Only explicit installer-controlled additions to the clean environment.
        permitted = {'BOOTIMG', 'ADDITIONAL_DTB_OVERLAY', 'ADDITIONAL_DTB_OVERLAY_OPT'}
        if set(env or {}) - permitted:
            raise ValueError('unsupported vendor environment override')
        environment = dict(ENV, HOME=str(self.root), TMPDIR=str(self.root))
        environment.update(env or {})
        result = self.runner(list(map(str, argv)), cwd=cwd, env=environment,
                             timeout=timeout, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=False)
        # Only the owned subprocess may generate the next graph. A failed command
        # terminates authorization rather than blessing partial outputs.
        if result.returncode:
            self.expected = None
            raise subprocess.CalledProcessError(result.returncode, argv, result.stdout)
        self._normalize_generated_rootfs_links()
        self._seal_modes()
        self.expected = snapshot(self.tree, self.owner)
        self.record('generated')
        return result.stdout.decode()

    def bind_vendor_adb(self, server):
        """Transform one authenticated assignment, recording the exact adapter.

        Vendor bootburn_adb.py starts/restarts adb unconditionally. Its tool
        string is replaced with our guard adapter, which owns no server lifecycle
        and checks our foreground PID/listener before each delegated command.
        """
        self.validate()
        source = self.tree / 'unified_flash/tools/flashtools/bootburn_t264_py/flash_utilities.py'
        original = source.read_text()
        needle = 'self.f_AdbTool = os.path.join(self.p_FlashPath, self.f_AdbTool + os_suffix)'
        if original.count(needle) != 1:
            raise ValueError('pinned vendor ADB assignment changed')
        adapter = self.root / 'vendor-adb-guard.py'
        client = self.root / 'adb_socket.py'
        client.write_bytes(Path(__file__).with_name('adb_socket.py').read_bytes())
        client.chmod(0o600)
        self.controls[client.name] = hashlib.sha256(client.read_bytes()).hexdigest()
        code = ("#!/usr/bin/python3\nimport runpy,sys\n"
                "sys.argv = [" + repr(str(client)) + ", '--pid', " + repr(str(server.process.pid)) +
                ", '--port', " + repr(str(server.port)) + ", '--'] + sys.argv[1:]\n"
                "runpy.run_path(" + repr(str(client)) + ", run_name='__main__')\n")
        with adapter.open('x') as f:
            f.write(code)
        adapter.chmod(0o700)
        self.controls[adapter.name] = hashlib.sha256(adapter.read_bytes()).hexdigest()
        replacement = 'self.f_AdbTool = ' + repr('/usr/bin/python3 ' + str(adapter))
        # The authenticated runner constructs raw strings then command.split().
        # Preserve the exact session-root prefix as one argv component. Do not
        # guess shell syntax: shlex would reinterpret remote shell fragments.
        split_site = 'commandList = command.split()'
        if original.count(split_site) != 2:
            raise ValueError('pinned vendor argv split sites changed')
        token = '__ADMIRAL_SESSION_' + os.urandom(16).hex() + '__'
        safe_split = ('commandList = [part.replace(' + repr(token) + ', ' + repr(str(self.root)) + ') '
                      'for part in command.replace(' + repr(str(self.root)) + ', ' + repr(token) + ').split()]')
        source.write_text(original.replace(needle, replacement).replace(split_site, safe_split))
        self.expected = snapshot(self.tree, self.owner)
        self.record('private-adb-adapter')
        self.vendor_server = server

    def remove_generated(self, relatives):
        self.validate()
        for relative in relatives:
            p = self.tree / relative
            if p.parent != self.tree / 'bootloader':
                raise ValueError('only fixed probe outputs may be removed')
            p.unlink(missing_ok=True)
        self.expected = snapshot(self.tree, self.owner)

    def record(self, stage):
        graph = json.dumps(self.expected, sort_keys=True, separators=(',', ':')).encode()
        data = {'stage': stage, 'inputs': self.inputs, 'tree': self.expected,
                'generated_sha256': hashlib.sha256(graph).hexdigest(),
                'source_hashes': {k:v['sha256'] for k,v in self.inputs.items() if 'sha256' in v},
                'authorization': None}
        p = self.root / 'preparation-manifest.json'
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner:
            os.close(fd)
            raise ValueError('unsafe preparation audit file')
        os.ftruncate(fd, 0)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.lock)
            os.close(self.fd)
            os.close(self.parent_fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
