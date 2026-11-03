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
import pwd
import re
import subprocess
import sys
import tarfile
import time
from nvidia_flash_tools.security import ENV, trusted_directory


# Content digests of unchanged files, keyed on what any write must change.
# A write always advances ctime, which cannot be set back without root (who is
# already trusted here), so an identical key means identical bytes. Files whose
# timestamps are within RACY_SECONDS of hashing are not cached: timestamps are
# coarse, so a write in the same tick could otherwise keep the key.
_DIGESTS = {}
RACY_SECONDS = 2
# Symlink resolution depends only on the set of links (real directories resolve
# lexically), so a link map identical to the last fully checked one is contained.
_VERIFIED_LINKS = {}


def _walk(root):
    """(path, lstat) for every entry below root, without following links."""
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                s = entry.stat(follow_symlinks=False)
                yield entry.path, s
                if stat.S_ISDIR(s.st_mode):
                    pending.append(entry.path)


def _digest(p, s):
    key = (str(p), s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    cached = _DIGESTS.get(key)
    if cached is not None:
        return cached
    now = time.time_ns()
    with open(p, 'rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    if max(s.st_mtime_ns, s.st_ctime_ns) < now - RACY_SECONDS * 1_000_000_000:
        _DIGESTS[key] = digest
    return digest


def snapshot(root, owner=0):
    """Every entry under root: mode, size and SHA256 for files, link targets.

    Uses os.scandir and plain strings: pathlib costs minutes on a full
    sample-rootfs tree. Symlink containment is checked with realpath exactly as
    Path.resolve() would.
    """
    base = os.path.abspath(os.fspath(root))
    rootfs = os.path.join(base, 'rootfs')
    result = {}
    links = []
    pending = [base]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path = entry.path
                s = entry.stat(follow_symlinks=False)
                if s.st_uid != owner or (not stat.S_ISLNK(s.st_mode) and s.st_mode & 0o022):
                    raise ValueError('untrusted workspace ownership/mode: ' + path)
                key = path[len(base) + 1:]
                if stat.S_ISREG(s.st_mode):
                    if s.st_nlink != 1:
                        raise ValueError('workspace hardlink refused')
                    result[key] = ['file', stat.S_IMODE(s.st_mode), s.st_size, _digest(path, s)]
                elif stat.S_ISDIR(s.st_mode):
                    result[key] = ['dir', stat.S_IMODE(s.st_mode)]
                    pending.append(path)
                elif stat.S_ISLNK(s.st_mode):
                    target = os.readlink(path)
                    links.append((key, target))
                    result[key] = ['link', target]
                else:
                    raise ValueError('workspace special file refused')
    signature = frozenset(links)
    if _VERIFIED_LINKS.get(base) != signature:
        for key, target in links:
            # Sample-rootfs absolute links refer to its target root, not host /.
            boundary = rootfs if key.split('/', 1)[0] == 'rootfs' else base
            if target.startswith('/'):
                resolved = os.path.realpath(os.path.join(boundary, target.lstrip('/')))
            else:
                resolved = os.path.realpath(os.path.join(os.path.dirname(os.path.join(base, key)), target))
            if resolved != boundary and not resolved.startswith(boundary + '/'):
                raise ValueError('workspace symlink escapes trust domain')
        _VERIFIED_LINKS[base] = signature
    return dict(sorted(result.items()))


_CVB_OUTPUT = r'admiral-[0-9a-f]{32}-cvb\.bin'


RECOVERY_IMAGE_SCRIPT = 'tools/ota_tools/version_upgrade/ota_make_recovery_img_dtb.sh'
RECOVERY_DSA_KEYGEN = ('\tssh-keygen -t dsa -N "" -f "${_initrd_dir}/${ssh_config_dir}/ssh_host_dsa_key"'
                       ' >/dev/null 2>&1;check_error\n')


# R39.2.1 flash.sh --no-flash --read-info writes readinfocmd.txt, then (with a
# board attached) parses chip_info.bin_bak, which only a real tegraflash run
# creates. A fresh probe deletes that file, so this exact exit is expected.
READINFO_CHIP_INFO_FAILURE = 'Parsing chip_info.bin information failed.'


def tolerable_failure(argv):
    """Allowlisted commands whose failure is data: the J401 cvb dump and its
    chkbdinfo decode, and flash.sh read-info command generation."""
    argv = [str(part) for part in argv]
    if (len(argv) == 7 and argv[:4] == ['./flash.sh', '--no-flash', '--read-info', '--usb-instance']
            and re.fullmatch(r'[0-9]+-[0-9.]+', argv[4]) and argv[6] == 'internal'):
        return True
    if len(argv) == 3 and argv[0] == './chkbdinfo' and argv[1] in ('-i', '-k'):
        return re.fullmatch(_CVB_OUTPUT, argv[2]) is not None
    if len(argv) > 3 and argv[:2] == ['/usr/bin/python3', './tegraflash.py'] and argv.count('--cmd') == 1:
        command = argv[argv.index('--cmd') + 1]
        return re.fullmatch(r'dump eeprom cvb ' + _CVB_OUTPUT + r'; reboot recovery', command) is not None
    return False


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

    def _archive(self, source, record, name, destination, members=None):
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
        # bzip2 is single-threaded; stream the same verified copy through
        # lbzip2 (a required host package) when present.
        decoder = None
        with copy.open('rb') as head:
            if head.read(3) == b'BZh' and Path('/usr/bin/lbzip2').is_file():
                decoder = subprocess.Popen(['/usr/bin/lbzip2', '-dc', str(copy)], env=ENV,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self._extract(copy, name, destination, decoder, members)
        except BaseException:
            if decoder:
                decoder.kill()
                decoder.wait()
            raise
        finally:
            if decoder:
                decoder.stdout.close()
                decoder.stderr.close()
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
        if members is not None:
            self.inputs[name]['members'] = {'count': len(members),
                'sha256': hashlib.sha256('\n'.join(sorted(members)).encode()).hexdigest()}

    def _extract(self, copy, name, destination, decoder, members=None):
        # members: the pinned subset of the authenticated archive to extract
        # (None extracts everything). The whole archive is still authenticated.
        with (tarfile.open(fileobj=decoder.stdout, mode='r|') if decoder else tarfile.open(copy)) as archive:
            seen = set()
            def authenticated_filter(member, target):
                normalized = posixpath.normpath(member.name)
                if normalized in seen and not member.isdir():
                    raise ValueError('duplicate archive member')
                seen.add(normalized)
                if members is not None:
                    if normalized not in members:
                        return None
                    if member.islnk() and posixpath.normpath(member.linkname) not in members:
                        raise ValueError('pinned rootfs member hardlinks outside the subset')
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
            if members is not None and not members <= seen:
                raise ValueError('pinned rootfs members missing from archive: %d' % len(members - seen))
        if decoder:
            # Drain trailing tar padding so lbzip2 can exit cleanly, then require success.
            while decoder.stdout.read(1024 * 1024):
                pass
            decoder.stdout.close()
            if decoder.wait() != 0:
                raise ValueError('archive decompression failed: ' + decoder.stderr.read().decode(errors='replace')[-500:])

    def prepare(self, bsp, rootfs, records, rootfs_members=None, cache=None):
        """Authenticated extraction + apply_binaries, or a verified cached copy.

        cache: a root-owned directory (normally <download cache>/prepared). A
        prepared tree depends only on the pinned archives, the member list, this
        preparation code and the host, which form the cache key. A hit is copied
        into this fresh session and must re-hash to the manifest recorded when it
        was built: every file's mode, size and SHA256 and every link target.
        """
        key = entry = None
        if cache is not None:
            key = self._prepare_key(records, rootfs_members)
            entry = Path(cache) / key
            if self._prepare_from_cache(Path(cache), entry, key):
                return self
        self._prepare_fresh(bsp, rootfs, records, rootfs_members)
        if cache is not None:
            self._store_prepared(Path(cache), entry, key)
        return self

    def _prepare_fresh(self, bsp, rootfs, records, rootfs_members):
        self._archive(bsp, records['archive'], 'bsp.tar', self.root)
        if not self.tree.is_dir() or self.tree.is_symlink():
            raise ValueError('missing vendor tree')
        target = self.tree / 'rootfs'
        target.mkdir(exist_ok=True)
        self._archive(rootfs, records['sample_rootfs'], 'rootfs.tar', target, rootfs_members)
        self._prepare_compressor()
        self._prepare_recovery_host_keys()
        self._seal_modes()
        self.expected = snapshot(self.tree, self.owner)
        self.run(['./apply_binaries.sh', '--rootless', '--target-overlay'])
        self.record('prepared')

    def _prepare_key(self, records, rootfs_members):
        import shutil
        try:
            host = Path('/etc/os-release').read_text()
        except OSError:
            host = ''
        material = {'schema': 1, 'records': {k: records[k] for k in ('archive', 'sample_rootfs')},
                    'members': None if rootfs_members is None else
                        hashlib.sha256('\n'.join(sorted(rootfs_members)).encode()).hexdigest(),
                    'code': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'lbzip2': bool(shutil.which('lbzip2', path=ENV['PATH'])),
                    'host': hashlib.sha256(host.encode()).hexdigest()}
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()

    def _prepare_from_cache(self, cache, entry, key):
        if not cache.is_dir():
            return False
        fd = trusted_directory(cache, owner=self.owner); os.close(fd)
        manifest = entry / 'manifest.json'
        if not (entry / 'Linux_for_Tegra').is_dir() or not manifest.is_file():
            return False
        fd = trusted_directory(entry, owner=self.owner); os.close(fd)
        record = json.loads(manifest.read_text())
        if record.get('key') != key:
            raise ValueError('prepared cache entry does not match its key')
        print('Using the cached prepared NVIDIA workspace ' + key[:12] + ' (verifying every file)...')
        self._copy_tree(entry / 'Linux_for_Tegra', self.root)
        self.expected = snapshot(self.tree, self.owner)
        if self.expected != record['tree']:
            self.expected = None
            raise ValueError('cached prepared workspace differs from its manifest; delete ' + str(entry))
        self.inputs = record['inputs']
        self.record('prepared-from-cache')
        return True

    def _store_prepared(self, cache, entry, key):
        self.validate()
        cache.mkdir(mode=0o700, exist_ok=True)
        fd = trusted_directory(cache, owner=self.owner); os.close(fd)
        staging = cache / ('.staging-' + os.urandom(8).hex())
        staging.mkdir(mode=0o700)
        try:
            self._copy_tree(self.tree, staging)
            (staging / 'manifest.json').write_text(json.dumps(
                {'key': key, 'inputs': self.inputs, 'tree': self.expected}, sort_keys=True))
            if snapshot(staging / 'Linux_for_Tegra', self.owner) != self.expected:
                raise ValueError('prepared cache copy differs from the session tree')
            os.rename(staging, entry)
        except OSError:
            if not (entry / 'manifest.json').is_file():
                raise
            # another session stored the same key first
        finally:
            if staging.exists():
                import shutil
                shutil.rmtree(staging)

    def _copy_tree(self, source, destination):
        # Same-filesystem copy (reflink where supported), modes and links kept.
        # Host tool, not a vendor command: never the injectable vendor runner.
        result = subprocess.run(['/bin/cp', '-a', '--reflink=auto', '--', str(source), str(destination) + '/'],
                                env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise ValueError('prepared workspace copy failed: ' + (result.stdout or b'').decode(errors='replace')[-500:])

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

    def _prepare_recovery_host_keys(self):
        # OpenSSH 10 (Ubuntu 26.04) removed DSA, so the recovery image builder's
        # DSA host key generation fails and stops flash.sh. The generated
        # sshd_config never lists a DSA HostKey; drop exactly that one line.
        script = self.tree / RECOVERY_IMAGE_SCRIPT
        if not script.is_file():
            return
        text = script.read_text()
        if text.count(RECOVERY_DSA_KEYGEN) != 1 or 'ssh_host_dsa_key' in text.replace(RECOVERY_DSA_KEYGEN, ''):
            raise ValueError('pinned recovery image DSA host key site changed')
        mode = stat.S_IMODE(script.stat().st_mode)
        script.write_text(text.replace(RECOVERY_DSA_KEYGEN, ''))
        script.chmod(mode)
        self.inputs['recovery_dsa_adapter'] = {'removed': RECOVERY_DSA_KEYGEN.strip(),
            'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest()}

    def _normalize_generated_rootfs_links(self):
        # apply_binaries overlays reintroduce target-absolute links. Convert all
        # of them before resolving chains, then snapshot rejects actual escapes.
        root = self.tree / 'rootfs'
        if not root.is_dir():
            return
        for path, s in _walk(str(root)):
            if stat.S_ISLNK(s.st_mode):
                target = os.readlink(path)
                if target.startswith('/'):
                    replacement = os.path.relpath(os.path.join(str(root), target.lstrip('/')), os.path.dirname(path))
                    os.unlink(path)
                    os.symlink(replacement, path)

    def _seal_modes(self):
        # chmod only what is group/other-writable: even a same-mode chmod bumps
        # ctime, which would invalidate every cached digest and force snapshot
        # to re-hash the whole tree after each vendor command.
        for path, s in _walk(str(self.tree)):
            if not stat.S_ISLNK(s.st_mode) and s.st_mode & 0o022:
                os.chmod(path, stat.S_IMODE(s.st_mode) & ~0o022)

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
        return self._run(argv, env, cwd, timeout, False)

    def run_tolerated(self, argv, env=None, cwd=None, timeout=1800):
        """Run an allowlisted carrier-evidence command whose failure is data.

        Returns (returncode, output) and keeps the workspace authorized; every
        other command still invalidates it on failure.
        """
        if not tolerable_failure(argv):
            raise ValueError('command failure may not be tolerated')
        return self._run(argv, env, cwd, timeout, True)

    def _run(self, argv, env, cwd, timeout, tolerate):
        self.validate()
        # flash.sh writes to an attached board unless told not to. Every
        # installer write goes through explicit, approved executors; flash.sh
        # only generates (--no-flash) or, for Thor, reads (--read-info).
        names = [str(part) for part in argv]
        if names and names[0] == './flash.sh' and '--no-flash' not in names and names[1:2] != ['--read-info']:
            raise ValueError('flash.sh would write to the attached board')
        cwd = Path(cwd or self.tree).absolute()
        if cwd != self.tree and self.tree not in cwd.parents:
            raise ValueError('vendor cwd outside workspace')
        # Only explicit installer-controlled additions to the clean environment.
        permitted = {'BOOTIMG', 'ADDITIONAL_DTB_OVERLAY', 'ADDITIONAL_DTB_OVERLAY_OPT'}
        if set(env or {}) - permitted:
            raise ValueError('unsupported vendor environment override')
        environment = dict(ENV, HOME=str(self.root), TMPDIR=str(self.root))
        # flash.sh decides root from $USER, not the uid; name the real user.
        environment['USER'] = environment['LOGNAME'] = pwd.getpwuid(os.geteuid()).pw_name
        environment.update(env or {})
        result = self.runner(list(map(str, argv)), cwd=cwd, env=environment,
                             timeout=timeout, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=False)
        # Only the owned subprocess may generate the next graph. A failed command
        # terminates authorization rather than blessing partial outputs.
        if result.returncode and not tolerate:
            self.expected = None
            sys.stderr.write((result.stdout or b'')[-4000:].decode(errors='replace') + '\n')
            raise subprocess.CalledProcessError(result.returncode, argv, result.stdout)
        self._normalize_generated_rootfs_links()
        self._seal_modes()
        self.expected = snapshot(self.tree, self.owner)
        self.record('generated-tolerated-failure' if result.returncode else 'generated')
        if tolerate:
            return result.returncode, result.stdout.decode(errors='replace')
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
