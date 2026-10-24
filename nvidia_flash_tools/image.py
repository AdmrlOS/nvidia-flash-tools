#!/usr/bin/env python3
"""Bounded raw GPT image I/O. Standard library only; no hardware discovery."""
import hashlib
import os
import stat
import struct
import uuid
import zlib

SECTOR = 512
CHUNK = 4 * 1024 * 1024


def digest(stream, length):
    result = hashlib.sha256()
    while length:
        data = stream.read(min(CHUNK, length))
        if not data:
            raise ValueError("truncated read")
        result.update(data)
        length -= len(data)
    return result.hexdigest()


def sha256(path):
    with open(path, "rb") as stream:
        return digest(stream, os.fstat(stream.fileno()).st_size)


def header(raw, lba, sectors):
    if len(raw) != SECTOR or raw[:8] != b"EFI PART":
        raise ValueError("missing GPT header")
    revision, size, crc, reserved = struct.unpack_from("<IIII", raw, 8)
    if revision != 0x10000 or size != 92 or reserved:
        raise ValueError("unsupported GPT header")
    checked = bytearray(raw[:size])
    struct.pack_into("<I", checked, 16, 0)
    if zlib.crc32(checked) != crc:
        raise ValueError("GPT header CRC mismatch")
    current, backup, first, last = struct.unpack_from("<QQQQ", raw, 24)
    entries, count, width, table_crc = struct.unpack_from("<QIII", raw, 72)
    if current != lba or backup >= sectors or first < 34 or first > last or last > sectors - 34:
        raise ValueError("GPT bounds mismatch")
    if count != 128 or width != 128:
        raise ValueError("only 128-entry GPT supported")
    return {"raw": raw, "backup": backup, "first": first, "last": last,
            "entries": entries, "table_crc": table_crc}


def inspect(path):
    with open(path, "rb") as stream:
        length = os.fstat(stream.fileno()).st_size
        if length % SECTOR or length < 68 * SECTOR:
            raise ValueError("unaligned or truncated image")
        sectors = length // SECTOR
        mbr = stream.read(SECTOR)
        if mbr[510:] != b"\x55\xaa" or mbr[450] != 0xee:
            raise ValueError("missing protective MBR")
        primary = header(stream.read(SECTOR), 1, sectors)
        if primary["backup"] != sectors - 1 or primary["entries"] != 2:
            raise ValueError("unexpected GPT placement")
        stream.seek(primary["entries"] * SECTOR)
        table = stream.read(16384)
        if zlib.crc32(table) != primary["table_crc"]:
            raise ValueError("GPT entries CRC mismatch")
        stream.seek((sectors - 1) * SECTOR)
        backup = header(stream.read(SECTOR), sectors - 1, sectors)
        if (backup["backup"] != 1 or backup["entries"] != sectors - 33
                or backup["first"] != primary["first"] or backup["last"] != primary["last"]
                or backup["raw"][56:72] != primary["raw"][56:72]):
            raise ValueError("GPT mirror mismatch")
        stream.seek(backup["entries"] * SECTOR)
        if stream.read(16384) != table or backup["table_crc"] != primary["table_crc"]:
            raise ValueError("GPT mirrored entries mismatch")
        parts = []
        guids = set()
        if primary["raw"][56:72] == bytes(16):
            raise ValueError("zero GPT disk GUID")
        for i in range(128):
            entry = table[i * 128:(i + 1) * 128]
            if entry[:16] == bytes(16):
                continue
            guid = entry[16:32]
            if guid == bytes(16) or guid in guids:
                raise ValueError("zero or duplicate partition GUID")
            guids.add(guid)
            start, end, attrs = struct.unpack_from("<QQQ", entry, 32)
            if start < primary["first"] or end > primary["last"] or start > end:
                raise ValueError("partition out of bounds")
            parts.append({"start": start, "end": end, "name": entry[56:128].decode("utf-16le").rstrip("\0"),
                          "type": str(uuid.UUID(bytes_le=entry[:16])), "attrs": attrs})
        ordered = sorted(parts, key=lambda p: p["start"])
        if any(a["end"] >= b["start"] for a, b in zip(ordered, ordered[1:])):
            raise ValueError("overlapping GPT partitions")
        return {"size": length, "primary": primary, "backup": backup, "table": table,
                "mbr": mbr, "partitions": parts}


def relocation(layout, capacity):
    if capacity % SECTOR or capacity < layout["size"]:
        raise ValueError("destination too small or not 512-byte aligned")
    sectors = capacity // SECTOR
    updates = []
    mbr = bytearray(layout["mbr"])
    struct.pack_into("<I", mbr, 458, min(sectors - 1, 0xffffffff))
    updates.append((0, bytes(mbr)))
    for kind, lba, other, entries in (("primary", 1, sectors - 1, 2),
                                      ("backup", sectors - 1, 1, sectors - 33)):
        raw = bytearray(layout[kind]["raw"])
        struct.pack_into("<QQ", raw, 24, lba, other)
        struct.pack_into("<Q", raw, 48, sectors - 34)
        struct.pack_into("<Q", raw, 72, entries)
        struct.pack_into("<I", raw, 16, 0)
        struct.pack_into("<I", raw, 16, zlib.crc32(raw[:92]))
        updates.append((lba * SECTOR, bytes(raw)))
    updates.append(((sectors - 33) * SECTOR, layout["table"]))
    return updates


def write_file_image(source, destination, expected_hash, expected_identity):
    """Real regular-file backend for offline qualification; NEVER block devices."""
    layout = inspect(source)
    if sha256(source) != expected_hash:
        raise ValueError("source SHA256 mismatch")
    fd = os.open(destination, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("file test backend refuses devices")
        identity = (info.st_dev, info.st_ino, info.st_size)
        if identity != tuple(expected_identity):
            raise ValueError("destination identity changed")
        if os.path.samefile(source, destination):
            raise ValueError("source equals destination")
        updates = relocation(layout, info.st_size)
        with os.fdopen(os.dup(fd), "r+b", buffering=0) as output, open(source, "rb") as inp:
            left = layout["size"]
            while left:
                block = inp.read(min(CHUNK, left))
                if not block:
                    raise ValueError("source truncated during write")
                if output.write(block) != len(block):
                    raise OSError("short destination write")
                left -= len(block)
            os.fsync(fd)
            output.seek(0)
            if digest(output, layout["size"]) != expected_hash:
                raise ValueError("raw image readback mismatch")
            # The old backup is no longer a GPT header; do not touch partition payload.
            if info.st_size != layout["size"]:
                output.seek(layout["size"] - 33 * SECTOR)
                output.write(bytes(33 * SECTOR))
            for offset, data in updates:
                output.seek(offset)
                if output.write(data) != len(data):
                    raise OSError("short GPT write")
            os.fsync(fd)
            for offset, data in updates:
                output.seek(offset)
                if output.read(len(data)) != data:
                    raise ValueError("GPT readback mismatch")
    finally:
        os.close(fd)
    result = inspect(destination)
    if result["partitions"] != layout["partitions"]:
        raise ValueError("partition map changed")
    with open(source, "rb") as inp, open(destination, "rb") as out:
        for part in layout["partitions"]:
            offset = part["start"] * SECTOR
            length = (part["end"] - part["start"] + 1) * SECTOR
            inp.seek(offset)
            out.seek(offset)
            if digest(inp, length) != digest(out, length):
                raise ValueError("partition readback mismatch")
    return result


def recovery_patches(source, capacity, directory):
    """Emit disk-sized GPT metadata for recovery-write.sh (no device access)."""
    from pathlib import Path
    directory = Path(directory)
    layout = inspect(source)
    updates = relocation(layout, capacity)
    primary = bytearray(layout["mbr"] + layout["primary"]["raw"] + layout["table"])
    backup = bytearray(layout["table"] + layout["backup"]["raw"])
    for offset, data in updates:
        if offset < len(primary):
            primary[offset:offset + len(data)] = data
        else:
            start = offset - (capacity - len(backup))
            backup[start:start + len(data)] = data
    directory.mkdir(parents=True, exist_ok=False)
    for name, content in (("primary.bin", primary), ("backup.bin", backup)):
        (directory / name).write_bytes(content)
    (directory / "SHA256SUMS").write_text("".join(sha256(directory / name) + "  " + name + "\n" for name in ("primary.bin", "backup.bin")))
    return directory
