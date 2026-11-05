"""Bounded, restartable full-GPT writer shared by real recovery and file tests."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile

from nvidia_flash_tools.image import CHUNK, digest, inspect, relocation, sha256


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


class Progress:
    """One line per few seconds: stage, percent, MB/s and ETA."""
    def __init__(self, stage, total, out=None, every=5.0):
        import sys, time
        self.stage, self.total, self.every = stage, max(total, 1), every
        self.out, self.clock = out or sys.stdout, time.monotonic
        self.start = self.last = self.clock()

    def update(self, done, final=False):
        now = self.clock()
        if not final and now - self.last < self.every:
            return
        self.last = now
        elapsed = max(now - self.start, 1e-6)
        rate = done / elapsed
        eta = (self.total - done) / rate if rate and done < self.total else 0
        print('%s: %5.1f%%  %7.1f / %.1f MB  %6.1f MB/s  ETA %d:%02d' % (
            self.stage, 100.0 * done / self.total, done / 1e6, self.total / 1e6,
            rate / 1e6, eta // 60, eta % 60), file=self.out, flush=True)


class RecoveryDisk:
    """Delegates to one authenticated native session at a time.

    reopen() replaces a failed session through the same authenticated open
    (board ID, helper hash, exclusive namespace checks). It never steals a lock:
    if the old helper still holds the namespace, the open fails closed.
    """
    def __init__(self, transport, disk, ecid, helper, helper_sha256):
        if disk['path'].startswith('/dev/nvme') is not True:
            raise ValueError('NVMe namespace required')
        self._open = (transport, disk, ecid, helper, helper_sha256)
        self.session = None
        self.reopen()

    def reopen(self):
        from nvidia_flash_tools.transport import check_remote_ecid_retrying
        transport, disk, ecid, helper, helper_sha256 = self._open
        if self.session is not None and not self.session.closed:
            self.session.abort()
        check_remote_ecid_retrying(transport, ecid)
        self.session = transport.open_helper(helper, helper_sha256, disk)

    def identity(self):
        return self.session.identity()

    def lock(self, identity):
        return self.session.lock(identity)

    def write(self, offset, data):
        return self.session.write(offset, data)

    def zero(self, offset, length):
        return self.session.zero(offset, length)

    def read(self, offset, length):
        return self.session.read(offset, length)

    def hash(self, offset, length):
        return self.session.hash(offset, length)

    def unlock(self):
        self.session.unlock()
        if hasattr(self.session, 'cleanup'):
            self.session.cleanup()


class FileDisk:
    """Real file I/O boundary for tests. Never accepts a block device."""
    def __init__(self, path):
        self.path = Path(path)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError('file test boundary refuses devices')
        self.stream = os.fdopen(fd, 'r+b', buffering=0)

    def identity(self):
        s = self.path.stat()
        f = os.fstat(self.stream.fileno())
        if (s.st_dev, s.st_ino, s.st_size) != (f.st_dev, f.st_ino, f.st_size):
            raise ValueError('file identity changed')
        return {'serial': str(f.st_ino), 'model': 'regular-file-test', 'capacity': f.st_size,
                'sector': 512, 'path': str(self.path.resolve()), 'device': f.st_dev}

    def lock(self, identity):
        import fcntl
        fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if self.identity() != identity:
            raise ValueError('identity changed before lock')

    def write(self, offset, data):
        self.stream.seek(offset)
        if self.stream.write(data) != len(data):
            raise OSError('short write')
        os.fsync(self.stream.fileno())

    def zero(self, offset, length):
        self.write(offset, bytes(length))

    def read(self, offset, length):
        self.stream.seek(offset)
        result = self.stream.read(length)
        if len(result) != length:
            raise ValueError('truncated readback')
        return result

    def hash(self, offset, length):
        self.stream.seek(offset)
        return digest(self.stream, length)

    def unlock(self):
        self.stream.close()


def write_image(source, disk, expected_hash, expected_identity, board_identity, journal, retries=3):
    """Resume is a revalidated hint, never authorization or proof of completion."""
    if retries not in (1, 2, 3):
        raise ValueError('bounded retries must be 1..3')
    layout = inspect(source)
    if sha256(source) != expected_hash:
        raise ValueError('source image SHA256 mismatch')
    capacity = expected_identity['capacity']
    updates = relocation(layout, capacity)
    contract = {'image_sha256': expected_hash, 'image_size': layout['size'],
                'board': board_identity, 'disk': expected_identity}
    journal = Path(journal).absolute()
    # A held directory FD and an owned, non-writable parent chain prevent rename
    # races. File-test journals use the same policy with the current test UID.
    from nvidia_flash_tools.security import trusted_directory
    directory_fd = trusted_directory(journal.parent, owner=os.geteuid())
    try:
        try:
            fd = os.open(journal.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(fd) as old:
                info = os.fstat(old.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o022 or info.st_nlink != 1):
                    raise ValueError('untrusted journal')
                if json.load(old)['identity'] != contract:
                    raise ValueError('resume identity/image changed')

        def save(stage, offset):
            temporary = '.journal-' + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            try:
                with os.fdopen(fd, 'w') as out:
                    json.dump({'identity': contract, 'stage': stage, 'offset': offset}, out, indent=2)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temporary, journal.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass

        def check_identity():
            if disk.identity() != expected_identity:
                raise ValueError('device binding identity changed')

        check_identity()
        disk.lock(expected_identity)
        # Keep failed sessions locked until RAM recovery restart; never steal a lock.
        save('writing', 0)
        written_hash = hashlib.sha256()
        zero_chunks = data_bytes = 0
        progress = Progress('NVMe write', layout['size'])
        with open(source, 'rb') as inp:
            offset = 0
            while offset < layout['size']:
                block = inp.read(min(CHUNK, layout['size'] - offset))
                if not block:
                    raise ValueError('source truncated')
                written_hash.update(block)
                expected = hash_bytes(block)
                # All-zero chunks (most of a sparse image) are filled by the
                # board itself; the board's readback hash still proves them.
                zero = not any(block) and hasattr(disk, 'zero')
                for attempt in range(retries):
                    check_identity()
                    try:
                        # Rehash every previous chunk, including resumed chunks. No skip
                        # based on journal offsets; interrupted GPT updates also recover.
                        if disk.hash(offset, len(block)) != expected:
                            if zero:
                                disk.zero(offset, len(block))
                            else:
                                disk.write(offset, block)
                        if disk.hash(offset, len(block)) != expected:
                            raise ValueError('chunk readback hash mismatch')
                        break
                    except (OSError, ValueError, __import__('subprocess').SubprocessError):
                        if attempt + 1 == retries:
                            raise
                        # A failed native request aborts its session; continue on a
                        # freshly authenticated one bound to the same disk.
                        if hasattr(disk, 'reopen'):
                            disk.reopen()
                            check_identity()
                            disk.lock(expected_identity)
                zero_chunks += zero
                data_bytes += 0 if zero else len(block)
                offset += len(block)
                save('writing', offset)
                progress.update(offset)
        progress.update(offset, final=True)
        print('NVMe write: %d MB sent as data, %d zero chunks filled on the board'
              % (data_bytes // 1000000, zero_chunks), flush=True)
        if written_hash.hexdigest() != expected_hash:
            raise ValueError('source changed during chunk write')
        # A second pass proves the original image range before changing any GPT byte.
        progress = Progress('NVMe verify', layout['size'])
        with open(source, 'rb') as inp:
            for offset in range(0, layout['size'], CHUNK):
                check_identity()
                block = inp.read(min(CHUNK, layout['size'] - offset))
                if disk.hash(offset, len(block)) != hash_bytes(block):
                    raise ValueError('full image bounded readback mismatch')
                progress.update(offset + len(block))
        progress.update(layout['size'], final=True)
        save('relocating-gpt', layout['size'])
        if capacity != layout['size']:
            check_identity()
            disk.write(layout['size'] - 33 * 512, bytes(33 * 512))
        for offset, block in updates:
            check_identity()
            disk.write(offset, block)
            if disk.read(offset, len(block)) != block:
                raise ValueError('GPT metadata readback mismatch')
        # Sparse regular file contains only actual readback metadata; inspect validates
        # both GPT CRCs, mirrors, map, bounds and disk GUID, without disk-sized RAM use.
        with tempfile.NamedTemporaryFile() as metadata:
            metadata.truncate(capacity)
            metadata.seek(0)
            metadata.write(disk.read(0, 17408))
            metadata.seek(capacity - 16896)
            metadata.write(disk.read(capacity - 16896, 16896))
            metadata.flush()
            result = inspect(metadata.name)
        if result['partitions'] != layout['partitions'] or result['table'] != layout['table']:
            raise ValueError('relocated GPT partition map changed')
        if result['primary']['raw'][56:72] != layout['primary']['raw'][56:72]:
            raise ValueError('disk GUID changed')
        with open(source, 'rb') as inp:
            for part in layout['partitions']:
                offset, left = part['start'] * 512, (part['end'] - part['start'] + 1) * 512
                inp.seek(offset)
                while left:
                    check_identity()
                    length = min(CHUNK, left)
                    if disk.hash(offset, length) != hash_bytes(inp.read(length)):
                        raise ValueError('partition payload readback mismatch')
                    offset, left = offset + length, left - length
        check_identity()
        save('verified-pending-hardware-acceptance', layout['size'])
        disk.unlock()
        return result
    finally:
        os.close(directory_fd)
