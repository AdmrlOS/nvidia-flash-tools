"""Filesystem and subprocess trust boundaries for privileged installer code."""
import os
from pathlib import Path
import stat

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
       'LC_ALL': 'C', 'LANG': 'C', 'PYTHONNOUSERSITE': '1'}


def trusted_directory(path, owner=0):
    """Return a held FD; reject symlink, writable or foreign-owned ancestors."""
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('untrusted parent traversal')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError('untrusted writable/foreign-owned directory: ' + str(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular_graph(tree):
    """Hash the complete tree, refusing links, devices and writable inputs."""
    from image import sha256
    tree = Path(tree)
    result = {}
    for entry in sorted(tree.rglob('*')):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('package symlink refused: ' + str(entry))
        if info.st_mode & 0o022:
            raise ValueError('writable package input: ' + str(entry))
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise ValueError('package hardlink refused: ' + str(entry))
            result[str(entry.relative_to(tree))] = sha256(entry)
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('non-regular package input: ' + str(entry))
    return result
