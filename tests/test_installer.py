#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nvidia_flash_tools.image import inspect, sha256, write_file_image, recovery_patches
from nvidia_flash_tools.install import authenticate, check_artifact, prerequisites


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o022)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.image = self.root / "source.img"
        with self.image.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024)
        subprocess.run(["sgdisk", "--clear", "--new=1:2048:4095", "--change-name=1:efi",
                        "--new=2:4096:8191", "--change-name=2:bootA",
                        "--new=3:8192:12287", "--change-name=3:bootB",
                        "--new=4:12288:16383", "--change-name=4:data",
                        "--new=5:16384:20479", "--change-name=5:main", str(self.image)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.image.open("r+b") as stream:
            stream.seek(2048 * 512)
            stream.write(b"actual partition payload" * 100)
        self.dest = self.root / "disk.img"
        with self.dest.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024)
        s = self.dest.stat()
        self.identity = (s.st_dev, s.st_ino, s.st_size)

    def tearDown(self):
        self.tmp.cleanup()
        os.umask(self.previous_umask)

    def test_real_file_write_relocation_and_sgdisk(self):
        before = inspect(self.image)
        result = write_file_image(self.image, self.dest, sha256(self.image), self.identity)
        self.assertEqual(before["partitions"], result["partitions"])
        output = subprocess.check_output(["sgdisk", "--verify", str(self.dest)], text=True)
        self.assertIn("No problems found", output)
        self.assertEqual(result["primary"]["backup"], self.dest.stat().st_size // 512 - 1)

    def test_recovery_patches(self):
        write_file_image(self.image, self.dest, sha256(self.image), self.identity)
        directory = recovery_patches(self.image, self.dest.stat().st_size, self.root / "patches")
        with self.dest.open("rb") as stream:
            self.assertEqual(stream.read(17408), (directory / "primary.bin").read_bytes())
            stream.seek(-16896, 2)
            self.assertEqual(stream.read(16896), (directory / "backup.bin").read_bytes())
        subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=directory, check=True, stdout=subprocess.PIPE)

    def test_bad_hash_does_not_write(self):
        before = sha256(self.dest)
        with self.assertRaisesRegex(ValueError, "SHA256"):
            write_file_image(self.image, self.dest, "0" * 64, self.identity)
        self.assertEqual(before, sha256(self.dest))

    def test_changed_disk_identity_does_not_write(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            write_file_image(self.image, self.dest, sha256(self.image), (0, 0, 0))
        self.assertEqual(self.dest.read_bytes()[:512], bytes(512))

    def test_corrupt_crc_refused(self):
        with self.image.open("r+b") as stream:
            stream.seek(528)
            stream.write(bytes(4))
        with self.assertRaisesRegex(ValueError, "CRC"):
            inspect(self.image)

    def test_recovery_script_refuses_non_device_without_writes(self):
        result = subprocess.run(["bash", str(Path(__file__).resolve().parent.parent.joinpath("recovery-write.sh")),
                                 "info", str(self.dest)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("whole NVMe namespace required", result.stderr)

    def test_truncation_and_corrupt_gpt(self):
        with self.image.open("r+b") as stream:
            stream.truncate(1024)
        with self.assertRaises(ValueError):
            inspect(self.image)

    def test_small_destination(self):
        self.dest.write_bytes(bytes(4096))
        s = self.dest.stat()
        with self.assertRaisesRegex(ValueError, "too small"):
            write_file_image(self.image, self.dest, sha256(self.image), (s.st_dev, s.st_ino, s.st_size))

    def test_symlink_refused(self):
        link = self.root / "link"
        link.symlink_to(self.dest)
        with self.assertRaises(OSError):
            write_file_image(self.image, link, sha256(self.image), self.identity)

    def test_manifest_tampering_and_authentication(self):
        m = self.root / "release.json"
        m.write_text(json.dumps({"schema": 1, "classification": "engineering-test-keys", "nvidia": {"version": "39.2.1"}}))
        pin = sha256(m)
        self.assertEqual(authenticate(m, pin)["schema"], 1)
        with self.assertRaisesRegex(ValueError, "differs"):
            authenticate(m, "0" * 64)
        with self.assertRaisesRegex(ValueError, "64"):
            authenticate(m, pin.upper())
        with patch("nvidia_flash_tools.install.run", side_effect=subprocess.CalledProcessError(1, "openssl")):
            with self.assertRaises(subprocess.CalledProcessError):
                authenticate(m, pin, "invalid-signature", "independent-key")

    def test_mocked_prerequisite_failures_are_explicit(self):
        with patch("nvidia_flash_tools.install.platform.freedesktop_os_release", return_value={"ID": "debian"}), patch("nvidia_flash_tools.install.platform.machine", return_value="aarch64"), patch("nvidia_flash_tools.install.shutil.which", return_value=None):
            issues = prerequisites()
        self.assertTrue(any("Ubuntu" in i for i in issues))
        self.assertTrue(any("x86_64" in i for i in issues))
        self.assertTrue(any("dpkg-query" in i for i in issues))

    def test_hash_truncation_refused(self):
        with self.assertRaisesRegex(ValueError, "size/SHA256"):
            check_artifact(self.image, {"size": 1, "sha256": "0" * 64})

    def test_live_path_requires_explicit_qualification(self):
        import argparse
        from nvidia_flash_tools.flow import install
        with self.assertRaisesRegex(ValueError, 'experimental first-test risk consent'):
            install(argparse.Namespace(engineering_hardware_qualified=False), {}, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
