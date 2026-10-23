"""Host side of the retained-FD recovery framed protocol."""
import hashlib
import struct
import select
import time
import os


class NativeSession:
    def __init__(self, process, identity, check_binding):
        self.process, self.expected, self.check_binding = process, dict(identity), check_binding
        self.closed = False
        self.total_deadline = time.monotonic() + 14400
        self.operation_deadline = self.total_deadline

    def identity(self):
        if self.closed:
            raise ValueError('exclusive recovery session lost')
        self.check_binding()
        if self.closed or self.process.poll() is not None:
            raise ValueError('exclusive recovery session lost')
        return dict(self.expected)

    def lock(self, identity):
        if self.identity() != identity:
            raise ValueError('recovery identity changed')

    def _read(self, n):
        result = bytearray()
        deadline = min(self.total_deadline, self.operation_deadline, time.monotonic() + 120)
        while len(result) < n:
            if time.monotonic() >= deadline: raise TimeoutError("native frame timeout")
            if hasattr(self.process.stdout, 'fileno'):
                try:
                    fd = self.process.stdout.fileno()
                except (OSError, ValueError):
                    fd = None
                if fd is not None and not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                    raise TimeoutError('native frame timeout')
            block = self.process.stdout.read(n - len(result))
            if not block:
                raise ValueError('truncated native frame')
            if time.monotonic() >= deadline: raise TimeoutError("native frame timeout")
            result.extend(block)
        return bytes(result)

    def _write(self, data):
        try:
            fd = self.process.stdin.fileno()
        except (AttributeError, OSError, ValueError):
            view = memoryview(data)
            deadline = min(self.total_deadline, self.operation_deadline, time.monotonic() + 120)
            while view:
                if time.monotonic() >= deadline: raise TimeoutError("native write timeout")
                try: count = self.process.stdin.write(view)
                except InterruptedError: continue
                if not isinstance(count, int) or not 0 < count <= len(view):
                    raise ValueError("invalid native write count")
                view = view[count:]
            self.process.stdin.flush()
            return
        os.set_blocking(fd, False)
        deadline = min(self.total_deadline, self.operation_deadline, time.monotonic() + 120)
        view = memoryview(data)
        while view:
            if time.monotonic() >= deadline: raise TimeoutError('native write timeout')
            if not select.select([], [fd], [], max(0, deadline - time.monotonic()))[1]:
                raise TimeoutError('native write timeout')
            try:
                count = os.write(fd, view)
            except (BlockingIOError, InterruptedError):
                continue
            if not isinstance(count, int) or not 0 < count <= len(view):
                raise ValueError('invalid native pipe write count')
            view = view[count:]

    def abort(self):
        self.closed = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except __import__('subprocess').TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()

    def request(self, op, offset, length, data=b''):
        try:
            return self._request(op, offset, length, data)
        except BaseException:
            self.abort()
            raise

    def _request(self, op, offset, length, data=b''):
        self.operation_deadline = min(self.total_deadline, time.monotonic() + 120)
        if time.monotonic() >= self.total_deadline: raise TimeoutError("native install runtime exceeded")
        self.identity()
        if (op not in (b'R', b'W') or offset < 0 or offset % 512 or
                not 0 < length <= 4194304 or length % 512 or
                offset + length > self.expected['capacity']):
            raise ValueError('native request outside bounds')
        if op == b'W' and len(data) != length:
            raise ValueError('native write length mismatch')
        digest = hashlib.sha256(data).digest() if data else bytes(32)
        self._write(struct.pack('>cQI32s', op, offset, length, digest) + data)
        count, expected = struct.unpack('>I32s', self._read(36))
        if count != (length if op == b'R' else 32):
            raise ValueError('invalid native response length')
        payload = self._read(count)
        if hashlib.sha256(payload).digest() != expected:
            raise ValueError('native response authentication failed')
        if op == b'W' and payload != digest:
            raise ValueError('native write readback mismatch')
        return payload

    def read(self, offset, length):
        return self.request(b'R', offset, length)

    def write(self, offset, data):
        self.request(b'W', offset, len(data), data)

    def hash(self, offset, length):
        return hashlib.sha256(self.read(offset, length)).hexdigest()

    def unlock(self):
        if not self.closed:
            try:
                self.operation_deadline = min(self.total_deadline, time.monotonic() + 120)
                self._write(struct.pack('>cQI32s', b'Q', 0, 0, bytes(32)))
                self.process.stdin.close()
                if self.process.wait(timeout=10):
                    raise ValueError('native session failed on close')
                self.closed = True
            except BaseException:
                self.abort()
                raise
