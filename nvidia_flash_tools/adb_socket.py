"""Owned smart sockets; shell-v2 only, SYNC, absolute operation deadlines."""
import argparse
import os
from pathlib import Path, PurePosixPath
import select
import socket
import stat
import struct
import sys
import time

LIMIT = 16 * 1024 * 1024
FRAME = 65536

def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0: raise TimeoutError('ADB operation deadline exceeded')
    return left

def exact(sock, size, deadline=None):
    if deadline is None: deadline = time.monotonic() + 30
    data = bytearray()
    while len(data) < size:
        sock.settimeout(remaining(deadline))
        try: block = sock.recv(size - len(data))
        except InterruptedError: continue
        remaining(deadline)
        if not block: raise ValueError('ADB disconnected / short frame')
        data.extend(block)
    return bytes(data)

def send(sock, data, deadline):
    data = memoryview(data)
    while data:
        sock.settimeout(remaining(deadline))
        try: count = sock.send(data)
        except InterruptedError: continue
        remaining(deadline)
        if count is None or count <= 0 or count > len(data):
            raise ValueError('ADB invalid socket write')
        data = data[count:]

def request(sock, service, deadline):
    data = service.encode()
    if len(data) > 65535: raise ValueError('ADB service too long')
    send(sock, ('%04x' % len(data)).encode() + data, deadline)
    status = exact(sock, 4, deadline)
    if status == b'FAIL':
        size = int(exact(sock, 4, deadline), 16)
        raise ValueError('ADB refused: ' + exact(sock, size, deadline).decode(errors='replace'))
    if status != b'OKAY': raise ValueError('malformed ADB status')

def owned_socket(pid, port, timeout=30, deadline=None):
    if deadline is None: deadline = time.monotonic() + timeout
    sock = socket.create_connection(('127.0.0.1', port), timeout=remaining(deadline))
    try:
        local = sock.getsockname()[1]
        ownership_deadline = min(deadline, time.monotonic() + 2)
        a, b = '0100007F:%04X' % port, '0100007F:%04X' % local
        while True:
            remaining(deadline)
            inodes = set()
            for p in Path('/proc/%d/fd' % pid).iterdir():
                try: link = os.readlink(p)
                except FileNotFoundError: continue
                if link.startswith('socket:['): inodes.add(link[8:-1])
            rows = [r.split() for r in Path('/proc/net/tcp').read_text().splitlines()[1:]]
            if any(r[1] == a and r[2] == b and r[3] == '01' and r[9] in inodes for r in rows): break
            if time.monotonic() >= ownership_deadline:
                raise ValueError('ADB accepted socket not owned by foreground server')
            time.sleep(min(0.01, remaining(ownership_deadline)))
        return sock
    except BaseException:
        sock.close()
        raise

def frame(sock, channel, data, deadline):
    if len(data) > FRAME: raise ValueError('oversized outgoing shell frame')
    send(sock, struct.pack('<BI', channel, len(data)) + data, deadline)

def fd_write(fd, data, deadline):
    old = os.get_blocking(fd)
    os.set_blocking(fd, False)
    try:
        data = memoryview(data)
        while data:
            if not select.select([], [fd], [], remaining(deadline))[1]: raise TimeoutError('ADB output deadline')
            try: count = os.write(fd, data)
            except (InterruptedError, BlockingIOError): continue
            if count <= 0 or count > len(data): raise ValueError('ADB output write failed')
            data = data[count:]
    finally: os.set_blocking(fd, old)

class Client:
    def __init__(self, pid, port, timeout=30):
        self.pid, self.port, self.timeout = pid, port, timeout

    @staticmethod
    def validate_serial(serial):
        if not serial or any(c not in '0123456789ABCDEFGHIJKLMNOPQRSTUV' for c in serial):
            raise ValueError('invalid NVIDIA serial')

    def connect(self, service, serial=None, deadline=None):
        if deadline is None: deadline = time.monotonic() + self.timeout
        sock = owned_socket(self.pid, self.port, deadline=deadline)
        try:
            if serial is not None:
                self.validate_serial(serial)
                request(sock, 'host:transport:' + serial, deadline)
            request(sock, service, deadline)
            return sock
        except BaseException:
            sock.close()
            raise

    def query(self, service, deadline=None):
        if deadline is None: deadline = time.monotonic() + self.timeout
        with self.connect(service, deadline=deadline) as sock:
            size = int(exact(sock, 4, deadline), 16)
            return exact(sock, size, deadline)

    def shell_socket(self, serial, command, deadline):
        self.validate_serial(serial)
        features = self.query('host-serial:' + serial + ':features', deadline).split(b',')
        if b'shell_v2' not in features: raise ValueError('target shell_v2 required; legacy shell forbidden')
        return self.connect('shell,v2,raw:' + command, serial, deadline)

    def shell_stream(self, serial, command, deadline, output, error, stdin=None, *, output_fds=None):
        with self.shell_socket(serial, command, min(deadline, time.monotonic()+self.timeout)) as sock:
            inputs = [sock] if stdin is None else [sock, stdin]
            if stdin is None: frame(sock, 4, b'', deadline)
            exit_code = None
            # Interactive native lifetime is separate from each bounded frame.
            progress = time.monotonic() + self.timeout
            total = 0
            while True:
                operation = min(deadline, progress) if stdin is not None else deadline
                ready = select.select(inputs, [], [], remaining(operation))[0]
                if not ready: raise TimeoutError('ADB shell deadline')
                if sock in ready:
                    sock.settimeout(remaining(operation))
                    try: first = sock.recv(1)
                    except InterruptedError: continue
                    remaining(operation)
                    if not first:
                        if exit_code is None: raise ValueError('ADB shell missing remote exit')
                        if exit_code: raise ValueError('ADB remote exit %d' % exit_code)
                        return
                    channel, size = struct.unpack('<BI', first + exact(sock, 4, operation))
                    if exit_code is not None: raise ValueError('ADB frame after remote exit')
                    if channel not in (1, 2, 3) or size > FRAME or (channel == 3 and size != 1):
                        raise ValueError('invalid ADB shell frame')
                    data = exact(sock, size, operation)
                    if channel == 3:
                        exit_code = data[0]
                        if stdin in inputs: inputs.remove(stdin)
                    else:
                        total += size
                        if stdin is None and total > LIMIT: raise ValueError('ADB shell output bound')
                        if output_fds is not None:
                            # Sink backpressure shares this frame's absolute budget.
                            fd_write(output_fds[channel - 1], data, operation)
                        else:
                            (output if channel == 1 else error)(data)
                if stdin in ready and stdin in inputs:
                    try: data = os.read(stdin, FRAME)
                    except InterruptedError: continue
                    frame(sock, 0 if data else 4, data, operation)
                    if not data: inputs.remove(stdin)
                # Only a complete frame/pipe chunk counts, never a partial byte.
                if stdin is not None: progress = time.monotonic() + self.timeout

    def shell(self, serial, command):
        deadline = time.monotonic() + self.timeout
        data = bytearray()
        self.shell_stream(serial, command, deadline, data.extend, lambda b: fd_write(2, b, deadline))
        return bytes(data)

    def push(self, serial, source, target):
        deadline = time.monotonic() + self.timeout
        path = PurePosixPath(str(target))
        if not path.is_absolute() or '..' in path.parts or '\x00' in str(target): raise ValueError('unsafe push destination')
        with self.connect('sync:', serial, deadline) as sock, open(source, 'rb') as inp:
            source_stat = os.fstat(inp.fileno())
            if not stat.S_ISREG(source_stat.st_mode): raise ValueError('push source must be regular')
            def remote_stat(p):
                raw = str(p).encode()
                send(sock, struct.pack('<4sI', b'STAT', len(raw)) + raw, deadline)
                tag, mode, size, mtime = struct.unpack('<4sIII', exact(sock, 16, deadline))
                if tag != b'STAT': raise ValueError('malformed ADB stat')
                return mode
            # SYNC v1 STAT is lstat. Fail closed on remote symlinks/special
            # nodes, including ancestors and the directory-resolved basename.
            def check(p):
                mode = 0
                for i in range(1, len(p.parts)):
                    mode = remote_stat(PurePosixPath(*p.parts[:i+1]))
                    if mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)): raise ValueError('unsafe remote push target')
                    if i < len(p.parts)-1 and not stat.S_ISDIR(mode): raise ValueError('push ancestor is not directory')
                return mode
            mode = check(path)
            if stat.S_ISDIR(mode):
                path = path / Path(source).name
                mode = check(path)
            elif str(target).endswith('/'): raise ValueError('push trailing slash requires existing directory')
            if mode and not stat.S_ISREG(mode): raise ValueError('push target is not regular')
            # Preserve ordinary source permissions but strip special bits.
            encoded = (str(path) + ',' + str(stat.S_IFREG | (source_stat.st_mode & 0o777))).encode()
            send(sock, struct.pack('<4sI', b'SEND', len(encoded)) + encoded, deadline)
            while data := inp.read(FRAME): send(sock, struct.pack('<4sI', b'DATA', len(data)) + data, deadline)
            send(sock, struct.pack('<4sI', b'DONE', 0), deadline)
            tag, size = struct.unpack('<4sI', exact(sock, 8, deadline))
            if tag != b'OKAY' or size:
                if size > FRAME: raise ValueError('oversized sync status')
                raise ValueError('ADB push failed: ' + exact(sock, size, deadline).decode(errors='replace'))

    def pull(self, serial, source, target):
        deadline = time.monotonic() + self.timeout
        encoded = str(source).encode()
        with self.connect('sync:', serial, deadline) as sock, open(target, 'xb') as out:
            total = 0
            send(sock, struct.pack('<4sI', b'RECV', len(encoded)) + encoded, deadline)
            while True:
                tag, size = struct.unpack('<4sI', exact(sock, 8, deadline))
                if tag == b'DONE' and size == 0: return
                if tag != b'DATA' or not 0 < size <= FRAME: raise ValueError('malformed ADB pull frame')
                total += size
                if total > LIMIT: raise ValueError('ADB pull size bound')
                out.write(exact(sock, size, deadline))

    def pipe(self, serial, command, total_seconds=14400):
        if not isinstance(total_seconds, int) or not 120 <= total_seconds <= 86400:
            raise ValueError("native install runtime outside policy")
        deadline = time.monotonic() + total_seconds
        self.shell_stream(serial, command, deadline, None, None,
                          sys.stdin.fileno(), output_fds=(1, 2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('args', nargs=argparse.REMAINDER)
    ns = parser.parse_args()
    client = Client(ns.pid, ns.port, timeout=120)
    args = ns.args
    if args[:1] == ['--']: args = args[1:]
    serial = None
    if args[:1] == ['-s']: serial, args = args[1], args[2:]
    if args == ['kill-server']: raise ValueError('vendor may not kill owned ADB server')
    if args in (['start-server'], ['host-features']): result = client.query('host:features')
    elif args == ['version']: result = b'Admiral owned ADB smart-socket adapter\n'
    elif args in (['devices'], ['devices', '-l']):
        result = b'List of devices attached\n' + client.query('host:devices-l' if '-l' in args else 'host:devices')
    elif args == ['wait-for-device'] and serial:
        deadline = time.monotonic() + client.timeout
        with client.connect('host-serial:' + serial + ':wait-for-any-device', deadline=deadline) as sock:
            if exact(sock, 4, deadline) != b'OKAY': raise ValueError('ADB wait failed')
        result = b''
    elif args[:1] == ['shell'] and serial:
        if args[1:2] == ['-T']: client.pipe(serial, ' '.join(args[2:])); return
        result = client.shell(serial, ' '.join(args[1:]))
    elif args[:1] == ['push'] and len(args) == 3 and serial:
        client.push(serial, args[1], args[2]); result = b''
    elif args[:1] == ['pull'] and len(args) == 3 and serial:
        target = Path(args[2])
        if target.is_dir(): target = target / Path(args[1]).name
        client.pull(serial, args[1], target); result = b''
    else: raise ValueError('unsupported owned ADB command: ' + repr(args))
    sys.stdout.buffer.write(result)

if __name__ == '__main__': main()
