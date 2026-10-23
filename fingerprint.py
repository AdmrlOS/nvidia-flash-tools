"""Admiral genimage GPT fingerprint beyond the authenticated full-image digest."""
import struct
import uuid
from image import inspect, digest


def admiral_image(path):
    layout = inspect(path)
    parts = layout['partitions']
    if [p['name'] for p in parts] != ['efi', 'bootA', 'bootB', 'data', 'main']:
        raise ValueError('not Admiral efi/bootA/bootB/data/main GPT')
    linux = '0fc63daf-8483-4772-8e79-3d69d8477de4'
    if [p['type'] for p in parts] != ['c12a7328-f81f-11d2-ba4b-00a0c93ec93b'] + [linux] * 4:
        raise ValueError('incorrect Admiral partition type GUIDs')
    for index, expected in ((3, '2e5f1d49-7e3b-4f16-b3b3-07d4c0c1a859'),
                            (4, '1e3ed9ec-8a9a-42ba-a92c-69fefd9cca07')):
        actual = str(uuid.UUID(bytes_le=layout['table'][index * 128 + 16:index * 128 + 32]))
        if actual != expected:
            raise ValueError('incorrect Admiral application partition UUID')
    a, b = parts[1:3]
    length = (a['end'] - a['start'] + 1) * 512
    if length != (b['end'] - b['start'] + 1) * 512:
        raise ValueError('unequal A/B partition sizes')
    with open(path, 'rb') as stream:
        stream.seek(a['start'] * 512); first = digest(stream, length)
        stream.seek(b['start'] * 512)
        if digest(stream, length) != first:
            raise ValueError('A/B partition payload mismatch')
        for part, label in ((parts[0], b'ADMRLESP   '), (a, b'BOOT       ')):
            stream.seek(part['start'] * 512)
            fat = stream.read(512)
            if fat[510:] != b'\x55\xaa' or label not in (fat[43:54], fat[71:82]):
                raise ValueError('FAT identity/boot signature mismatch')
        stream.seek(parts[3]['start'] * 512 + 1024 + 56)
        if stream.read(2) != b'\x53\xef':
            raise ValueError('data is not ext4')
        stream.seek(parts[4]['start'] * 512 + 65536 + 64)
        if stream.read(8) != b'_BHRfS_M':
            raise ValueError('main is not Btrfs')
    return layout
