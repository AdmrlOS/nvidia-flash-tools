"""Selected-device recovery transports; no unbound adb/SSH operations."""
import re
import shlex
import subprocess
import os
import socket
import time
import hashlib
from pathlib import Path
from nvidia_flash_tools.security import ENV

# Seconds between remote ECID re-reads during one Orin SSH helper session.
REMOTE_ECID_INTERVAL = 60


def execute(argv, timeout=120, **kwargs):
    if not Path(argv[0]).is_absolute():
        raise ValueError('absolute authenticated host tool required')
    if 'env' in kwargs:
        raise ValueError('transport environment override refused')
    return subprocess.run([str(x) for x in argv], check=True, timeout=timeout,
                          env=dict(ENV), cwd='/',
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def adb_serial(ecid):
    # NVIDIA bootburn_lib.py:521-557 uses numeric base32, NOT RFC4648 base32.
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,32}", ecid) or int(ecid, 16) == 0:
        raise ValueError("invalid ECID")
    value, result = int(ecid, 16), ""
    while value:
        result = "0123456789ABCDEFGHIJKLMNOPQRSTUV"[value % 32] + result
        value //= 32
    return result


def usb_device(port, sysfs=Path('/sys/bus/usb/devices')):
    if not re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*', port):
        raise ValueError('invalid physical USB port')
    return (sysfs / port).resolve(strict=True)


class PrivateADBServer:
    """Foreground owned server; no start-server/kill-server or ambient socket.

    Bundled 28.0.0 help documents -L (server) and -H/-P (client); binary
    contains server/nodaemon. Linux /proc binds the listening inode to our PID.
    """
    def __init__(self, binary, expected_sha256, workspace, popen=subprocess.Popen):
        workspace.validate()
        self.workspace, self.binary = workspace, str(Path(binary).absolute())
        from nvidia_flash_tools.image import sha256
        if sha256(self.binary) != expected_sha256:
            raise ValueError('ADB authentication failed')
        if Path(self.binary) not in [workspace.tree / k for k, v in workspace.expected.items()
                                     if v[0] == 'file' and v[-1] == expected_sha256]:
            raise ValueError('ADB not in authenticated workspace')
        reservation = socket.socket()
        reservation.bind(('127.0.0.1', 0))
        self.port = reservation.getsockname()[1]
        reservation.close()
        self.process = popen([self.binary, '-L', 'tcp:127.0.0.1:' + str(self.port),
                              'server', 'nodaemon'], env=dict(ENV, HOME=str(workspace.root)),
                             cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True)
        self.clients = ['-H', '127.0.0.1', '-P', str(self.port)]
        self.adapter = str(Path(__file__).with_name('adb_socket.py').resolve())
        try:
            deadline = time.monotonic() + 10
            while True:
                if self.process.poll() is not None:
                    raise ValueError('private ADB server exited')
                try:
                    self.check()
                    break
                except ValueError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.02)
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.process.poll() is not None:
            raise ValueError('owned ADB server lost')
        inodes = set()
        for p in Path('/proc/' + str(self.process.pid) + '/fd').iterdir():
            try:
                link = os.readlink(p)
            except FileNotFoundError:
                continue
            if link.startswith('socket:['):
                inodes.add(link[8:-1])
        expected = '0100007F:' + format(self.port, '04X')
        rows = [l.split() for l in Path('/proc/net/tcp').read_text().splitlines()[1:]]
        listeners = [r for r in rows if r[1] == expected and r[3] == '0A']
        if len(listeners) != 1 or listeners[0][9] not in inodes:
            raise ValueError('private loopback listener is not owned by server subprocess')

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ADB:
    def __init__(self, binary, ecid, port, runner=execute, sysfs=Path('/sys/bus/usb/devices'), server=None):
        if not Path(binary).is_absolute():
            raise ValueError('absolute authenticated ADB tool required')
        self.owner = server
        if server is not None and str(Path(binary).absolute()) != server.binary:
            raise ValueError('ADB client/server binary mismatch')
        self.server = server.clients if server else ['-H', '127.0.0.1', '-P', '5038']
        self.binary, self.ecid, self.serial, self.port = str(binary), ecid, adb_serial(ecid), port
        self.run, self.sysfs = runner, sysfs

    def _command(self, args):
        if self.owner is not None:
            return ['/usr/bin/python3', self.owner.adapter, '--pid', str(self.owner.process.pid), '--port', str(self.owner.port), '--', *args]
        return [self.binary, *self.server, *args]

    def bind(self, timeout=120):
        if self.owner is not None:
            self.owner.check()
        elif self.run is execute:
            raise ValueError('owned private ADB server required')
        device = usb_device(self.port, self.sysfs)
        devices = [p.name for p in self.sysfs.iterdir() if (p / 'idVendor').is_file() and (p / 'idVendor').read_text().strip() == '0955']
        if devices != [self.port]:
            raise ValueError('require exactly one NVIDIA USB recovery endpoint')
        if (device / 'idVendor').read_text().strip() != '0955':
            raise ValueError('selected USB port is not NVIDIA')
        if (device / 'serial').read_text().strip() != self.serial:
            raise ValueError('ADB physical USB serial changed')
        output = self.run(self._command(['devices']), timeout=timeout).decode()
        devices = [line.split() for line in output.splitlines()[1:] if line.strip()]
        if devices != [[self.serial, 'device']]:
            raise ValueError('require exactly one authorized ECID-bound ADB device')

    def wait_ready(self, timeout=120):
        """Bounded readiness retry; never switch port, serial or private server."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError('Thor recovery transport not ready on selected topology')
            if self.owner is not None:
                self.owner.check()
            devices = [p for p in self.sysfs.iterdir() if (p/'idVendor').is_file()
                       and (p/'idVendor').read_text().strip() == '0955']
            if any(p.name != self.port for p in devices) or len(devices) > 1:
                raise ValueError('unexpected NVIDIA endpoint during recovery wait')
            if devices:
                serial = devices[0]/'serial'
                if serial.exists() and serial.read_text().strip() != self.serial:
                    raise ValueError('ADB physical USB serial changed')
                if serial.exists():
                    try:
                        self.bind(timeout=left)
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Thor recovery ready deadline exceeded')
                        return
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                        pass
                    except ValueError as exc:
                        # Only not-yet-authorized device listing is transient.
                        if str(exc) != 'require exactly one authorized ECID-bound ADB device':
                            raise
            time.sleep(min(.25, max(0, deadline-time.monotonic())))

    def shell(self, *args):
        self.bind()
        return self.run(self._command(['-s', self.serial, 'shell', shlex.join(args)]))

    def push(self, source, target):
        self.bind()
        self.run(self._command(['-s', self.serial, 'push', str(source), str(target)]))

    def open_helper(self, helper, helper_sha256, identity):
        """Stage authenticated helper in fresh private RAM dir; keep shell pipe.

        No helper pathname is reused, and no disk is opened by a shell utility.
        """
        import secrets
        from nvidia_flash_tools.image import sha256
        if self.owner is None:
            raise ValueError('owned server required for native session')
        self.bind()
        if sha256(helper) != helper_sha256:
            raise ValueError('native helper binary hash differs from approval')
        path = identity['path']
        if not re.fullmatch(r'/dev/nvme[0-9]+n[0-9]+', path):
            raise ValueError('whole NVMe namespace required')
        check_remote_ecid(self, self.ecid)
        directory = self.shell('/bin/mktemp', '-d', '/tmp/admiral-' + secrets.token_hex(16) + '-XXXXXX').decode().strip()
        if not re.fullmatch(r'/tmp/admiral-[0-9a-f]{32}-[A-Za-z0-9]{6}', directory):
            raise ValueError('invalid private recovery directory')
        target = directory + '/recovery-io'
        try:
            self.push(helper, target)
            actual = self.shell('/bin/sha256sum', target).decode().split()
            if actual != [helper_sha256, target]:
                raise ValueError('pushed native helper authentication failed')
            self.shell('/bin/chmod', '0700', target)
            args = [target, 'session', path, str(identity['major']), str(identity['minor']),
                    str(identity['capacity']), '0', '512', identity['serial'], identity['model'], identity['device']]
            self.bind()
            process = subprocess.Popen(self._command(['-s', self.serial, 'shell', '-T', shlex.join(args)]),
                                       env=dict(ENV), cwd='/', stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, bufsize=0)
            from nvidia_flash_tools.native_session import NativeSession
            def binding():
                self.bind()
                check_remote_ecid(self, self.ecid)
            result = NativeSession(process, identity, binding)
            result.cleanup = lambda: self.shell('/bin/rm', '-rf', directory)
            return result
        except BaseException:
            try:
                self.shell('/bin/rm', '-rf', directory)
            except (ValueError, OSError, subprocess.SubprocessError):
                pass  # Lost RAM server: directory is disposable; preserve failure.
            raise



class SSH:
    def __init__(self, interface, port, known_hosts, runner=execute,
                 sysfs=Path('/sys/bus/usb/devices'), netfs=Path('/sys/class/net'), ecid=None):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', interface):
            raise ValueError('invalid USB network interface')
        self.interface, self.port = interface, port
        self.sysfs, self.netfs, self.run = sysfs, netfs, runner
        # Dedicated qualified recovery host-key file; no LAN/global host-key bypass.
        self.options = ['-F', '/dev/null', '-B', interface,
                        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
                        '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                        '-o', 'ControlPersist=no', '-o', 'GlobalKnownHostsFile=/dev/null',
                        '-o', 'KnownHostsCommand=none', '-o', 'CanonicalizeHostname=no',
                        '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes',
                        '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                        '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=10', '-o',
                        'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known_hosts)]
        self.ecid = ecid
        self.options += ['-o', 'HostKeyAlias=admiral-orin-recovery',
                         '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UpdateHostKeys=no',
                         '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                         '-o', 'RequestTTY=no']
        self.host = 'root@fe80::1%' + interface

    def _command(self, command):
        # Pinned recovery image's public engineering root password, not a user
        # credential. -p prevents password input from consuming helper stdin.
        return ['/usr/bin/sshpass', '-p', 'root', '/usr/bin/ssh', '-T',
                *self.options, self.host, command]

    def wait_ready(self, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.bind()
            try:
                if self.shell('/bin/true') == b'':
                    return
            except subprocess.CalledProcessError:
                pass
            time.sleep(.25)
        raise TimeoutError('selected Orin USB SSH recovery not ready')

    def bind(self):
        devices = [p.name for p in self.sysfs.iterdir() if (p/'idVendor').exists()
                   and (p/'idVendor').read_text().strip() == '0955']
        if devices != [self.port]:
            raise ValueError('require exactly one NVIDIA USB recovery device')
        usb = usb_device(self.port, self.sysfs)
        device = (self.netfs / self.interface / 'device').resolve(strict=True)
        if usb not in device.parents:
            raise ValueError('SSH interface no longer belongs to selected physical USB device')
        if (usb / 'idVendor').read_text().strip() != '0955':
            raise ValueError('USB network device is not NVIDIA')

    def shell(self, *args, timeout=None):
        self.bind()
        if timeout is None:
            return self.run(self._command(shlex.join(args)))
        return self.run(self._command(shlex.join(args)), timeout=timeout)

    def push(self, source, target):
        self.bind()
        # No SCP protocol/target shell ambiguity; checked SSH stdin copy to RAM.
        with open(source, 'rb') as stream:
            self.run(self._command('umask 077; cat > ' + shlex.quote(str(target))), stdin=stream)

    def open_helper(self, helper, helper_sha256, identity):
        import secrets
        from nvidia_flash_tools.image import sha256
        from nvidia_flash_tools.native_session import NativeSession
        self.bind()
        if self.ecid is None or sha256(helper) != helper_sha256:
            raise ValueError('Orin helper/ECID not authenticated')
        check_remote_ecid(self, self.ecid)
        if not re.fullmatch(r'/dev/nvme[0-9]+n[0-9]+', identity['path']):
            raise ValueError('whole NVMe namespace required')
        directory = self.shell('/bin/mktemp','-d','/tmp/admiral-'+secrets.token_hex(16)+'-XXXXXX').decode().strip()
        if not re.fullmatch(r'/tmp/admiral-[0-9a-f]{32}-[A-Za-z0-9]{6}',directory):
            raise ValueError('invalid Orin helper RAM directory')
        target = directory+'/recovery-io'
        try:
            self.push(helper,target)
            if self.shell('/usr/bin/sha256sum',target).decode().split() != [helper_sha256,target]:
                raise ValueError('Orin staged helper hash mismatch')
            self.shell('/bin/chmod','0700',target)
            args = [target,'session',identity['path'],str(identity['major']),str(identity['minor']),
                    str(identity['capacity']),'0','512',identity['serial'],identity['model'],identity['device']]
            self.bind(); check_remote_ecid(self,self.ecid)
            process = subprocess.Popen(self._command('exec '+shlex.join(args)), env=dict(ENV),cwd='/',
                                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                       close_fds=True,bufsize=0)
            # The local USB binding (same physical device and interface) is
            # checked on every request. The remote ECID read is a new SSH login
            # (~5-7 s): at most once a minute, plus on open. The helper runs in
            # this one long-lived SSH session, which ends if the board goes away.
            last_remote = [time.monotonic()]
            def binding():
                self.bind()
                if time.monotonic() - last_remote[0] >= REMOTE_ECID_INTERVAL:
                    check_remote_ecid_retrying(self, self.ecid)
                    last_remote[0] = time.monotonic()
            result = NativeSession(process,identity,binding)
            result.cleanup = lambda: self.shell('/bin/rm','-rf',directory)
            return result
        except BaseException:
            self.shell('/bin/rm','-rf',directory)
            raise


def check_remote_ecid(transport, ecid):
    # Both sides must expose the pinned NVIDIA helper; missing helper fails closed.
    raw = transport.shell('/bin/bash', '/bin/nv_fuse_read.sh', 'br_cid').decode().strip()
    match = re.fullmatch(r'BR_CID: (0x[0-9a-fA-F]{25})', raw)
    # nv_fuse_read.sh print_br_cid emits the lower 100-bit manufacturing ID;
    # flash.sh's bootrom UID also contains seven high metadata hex digits.
    expected = int(ecid, 16) & ((1 << 100) - 1)
    if not match or int(match[1], 16) != expected:
        raise ValueError('RAM recovery ECID mismatch or unsupported fuse-helper output')


def check_remote_ecid_retrying(transport, ecid, pauses=(2, 5), sleep=time.sleep):
    """Re-read the board ID over a fresh SSH login while a helper session is open.

    A login that fails (dropped preauth, timeout) proves nothing either way, so it
    is retried; it must not tear down the exclusive helper session. A completed
    read with the wrong ID (ValueError) is never retried.
    """
    for pause in (*pauses, None):
        try:
            return check_remote_ecid(transport, ecid)
        except subprocess.SubprocessError:
            if pause is None:
                raise
            sleep(pause)
