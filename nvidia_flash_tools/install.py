#!/usr/bin/env python3
"""Admiral Jetson engineering installer: offline authenticated preparation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from nvidia_flash_tools.image import inspect, sha256, digest, CHUNK

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = "abootimg binfmt-support binutils cpio cpp device-tree-compiler dosfstools e2fsprogs file gdisk iproute2 iputils-ping lbzip2 libxml2-utils netcat-openbsd nfs-kernel-server openssl parted python3-yaml qemu-user-static rsync sshpass udev usbutils uuid-runtime whois xmlstarlet xxd zstd zlib1g python3-usb lz4 python-is-python3".split()


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def authenticate(manifest, pin, signature=None, public_key=None):
    # A pin delivered separately authenticates the exact release manifest.
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("manifest pin must be exactly 64 lowercase hex digits")
    if sha256(manifest) != pin:
        raise ValueError("manifest SHA256 differs from independently supplied release pin")
    if bool(signature) != bool(public_key):
        raise ValueError("signature and independently trusted public key must be supplied together")
    if signature:
        run(["openssl", "dgst", "-sha256", "-verify", public_key,
             "-signature", signature, manifest])
    data = json.loads(manifest.read_text())
    if data["schema"] != 1 or data["nvidia"]["version"] != "39.2.1":
        raise ValueError("unsupported release manifest")
    if data["classification"] != "engineering-test-keys":
        raise ValueError("this installer does not qualify production trust")
    return data


def prerequisites():
    release = platform.freedesktop_os_release()
    problems = []
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in ("22.04", "24.04"):
        problems.append("use a native Ubuntu 22.04/24.04 host")
    if Path('/proc/sys/fs/binfmt_misc/WSLInterop').exists() or 'microsoft' in platform.release().lower():
        problems.append('WSL is not a qualified physical host')
    if shutil.which('systemd-detect-virt'):
        detected = subprocess.run(['systemd-detect-virt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if detected.returncode == 0:
            problems.append('VM/container host is not qualified: ' + detected.stdout.strip())
    else:
        problems.append('systemd-detect-virt missing; physical host not established')
    if platform.machine() != "x86_64":
        problems.append("use x86_64: pinned NVIDIA host tools are x86-64")
    if shutil.which("dpkg-query"):
        missing = []
        for package in PACKAGES:
            try:
                if run(["dpkg-query", "-W", "-f=${Status}", package]).strip() != "install ok installed":
                    missing.append(package)
            except subprocess.CalledProcessError:
                missing.append(package)
        if missing:
            problems.append("missing Ubuntu packages: " + " ".join(missing))
            problems.append("operator action (not run): sudo apt-get install " + " ".join(missing))
    else:
        problems.append("dpkg-query missing; cannot establish NVIDIA prerequisites")
    return problems


def check_artifact(path, record):
    if not path.is_file() or path.is_symlink():
        raise ValueError("artifact must be a regular, non-symlink file: " + str(path))
    if path.stat().st_size != record["size"] or sha256(path) != record["sha256"]:
        raise ValueError("artifact size/SHA256 mismatch: " + path.name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("check", "download", "prepare", "install"))
    p.add_argument("--manifest", type=Path, default=ROOT / "release.json")
    p.add_argument("--manifest-sha256", required=True, help="obtain independently from release operator")
    p.add_argument("--signature", type=Path)
    p.add_argument("--public-key", type=Path)
    p.add_argument("--board", required=True, choices=("thor", "orin", "orin-nx"))
    p.add_argument("--image", type=Path)
    p.add_argument("--download-dir", type=Path)
    p.add_argument("--download", action="store_true", help="prepare: fetch pinned NVIDIA inputs after consent")
    p.add_argument("--accept-nvidia-license", action="store_true", help="explicit acknowledgement after reviewing NVIDIA release license terms")
    p.add_argument("--nvidia-archive", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument('--sample-rootfs', type=Path)
    p.add_argument('--vendor-tree', type=Path)
    p.add_argument('--usb-port')
    p.add_argument('--usb-interface')
    p.add_argument('--known-hosts', type=Path)
    p.add_argument('--disk')
    p.add_argument('--helper', type=Path, help='authenticated static native helper binary')
    p.add_argument('--journal', type=Path)
    args = p.parse_args()
    release = authenticate(args.manifest, args.manifest_sha256, args.signature, args.public_key)
    print("[1/5] Authenticated manifest using operator's independent SHA256 pin.")
    if args.action == 'download' or (args.action == 'prepare' and args.download):
        from nvidia_flash_tools.download import guided
        guided(args, release)
        if args.action == 'download':
            print('Pinned NVIDIA inputs verified. No vendor execution or device operations performed.')
            return 0
    if args.image is None and args.action != 'prepare':
        raise ValueError('--image required for check/install')
    if args.image is None:
        from nvidia_flash_tools.flow import prepare
        prepare(args, release)
        return 0
    check_artifact(args.image, release["boards"][args.board]["image"])
    from nvidia_flash_tools.fingerprint import admiral_image
    admiral_image(args.image)
    print("[2/5] Full raw image SHA256, size, primary/backup GPT CRC and partition bounds verified.")
    if args.nvidia_archive:
        check_artifact(args.nvidia_archive, release["nvidia"]["archive"])
        print("[3/5] Pinned NVIDIA 39.2.1 driver archive verified (not executed).")
    else:
        print("[3/5] NVIDIA archive NOT supplied / NOT verified.")
    issues = prerequisites()
    print("[4/5] Host prerequisite report:")
    print("\n".join("  " + issue for issue in issues) if issues else "  Ubuntu/x86_64/vendor package prerequisites present.")
    print("[5/5] Hardware stages UNVERIFIED: EEPROM/carrier/SKU, security fuses, recovery selection, firmware readback, NVMe identity, boot.")
    from nvidia_flash_tools.flow import install, prepare
    if args.action == "install":
        install(args, release, issues)
    if args.action == "prepare":
        prepare(args, release)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        sys.exit(1)
