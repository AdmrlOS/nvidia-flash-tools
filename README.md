# NVIDIA flash tools

Install an Admiral disk image on a **Jetson AGX Thor** or **Jetson AGX Orin**
reference kit using the pinned NVIDIA Jetson Linux 39.2.1 recovery tools.

**Back up first: installation replaces QSPI boot firmware and erases the entire
selected NVMe. Not tested on physical devices:** USB recovery, firmware acceptance,
first boot, CUDA and interrupted-flash recovery need a hardware test. Keep stable
power and disable host sleep. Secure Boot must already be disabled; the installer
checks fuses and does not burn fuses, enroll keys or change security settings.

## 1. Set up the Ubuntu host

Use a separate **physical Ubuntu 22.04/24.04/26.04 x86_64 PC**, at least 40 GiB free,
internet access and a direct USB data cable. Flashing from macOS, ARM, a VM, WSL
or a container is not supported. Python uses the standard library; no pip install.

1. Obtain `nvidia-flash-tools.tar.gz`, its independently supplied archive SHA256,
   the independently supplied `engineering-manifest.json` SHA256, and the matching
   Admiral `.img` from the release operator. Image URLs are not configured in this
   bundle. The manifest SHA256 is the `--bundle-pin`, **not** the archive SHA256.
2. In the download directory, replace these two values with the supplied pins:

   ```sh
   ARCHIVE_SHA256='REPLACE_WITH_INDEPENDENT_ARCHIVE_SHA256'
   BUNDLE_PIN='REPLACE_WITH_INDEPENDENT_MANIFEST_SHA256'
   printf '%s  %s\n' "$ARCHIVE_SHA256" nvidia-flash-tools.tar.gz | sha256sum -c -
   ```

   Continue only after `OK`. Authenticate before extracting or running Python.
3. Extract into a new root-owned directory. If it exists, choose a new name:

   ```sh
   sudo mkdir -m 0755 /opt/nvidia-flash-tools
   sudo tar --no-same-owner -xzf nvidia-flash-tools.tar.gz -C /opt/nvidia-flash-tools
   cd /opt/nvidia-flash-tools/admiral-jetson-installer
   ```

Keep this terminal open so the pin variables remain available. All extraction,
session and cache ancestors must be non-group/other-writable and root-owned.

## 2A. Install on AGX Thor

Only **P3834-0008 + NVIDIA P4071-0000 carrier**, image
`admiral-jetson-agx-thor.img` matching this bundle's `boards.thor.image` record.

1. On the existing kit, personally observe **Secure Boot Disabled** in UEFI or
   `mokutil --sb-state`. Shut down before fitting/changing the NVMe.
2. On the Ubuntu host, check the supplied image without accessing a device:

   ```sh
   python3 thor.py check --bundle-pin "$BUNDLE_PIN"
   ```

   Enter the image's absolute path. Expect `Admiral image: full SHA256, both GPTs
   and partition fingerprint verified.` Review the host report; if packages are
   missing, review/run the printed `sudo apt-get install ...` command and repeat.
3. Connect the recovery USB-C **beside HDMI (5a)** to the host and power to the
   other USB-C **(5b)**. Do not use the debug USB-C under the lid.
4. With power connected, hold the middle **Force Recovery** button, press/release
   the right **Reset** button, then release Force Recovery.
5. Confirm one NVIDIA/APX endpoint; disconnect other NVIDIA USB devices:

   ```sh
   lsusb -d 0955:
   ```

6. Start installation:

   ```sh
   sudo /usr/bin/python3 thor.py install --bundle-pin "$BUNDLE_PIN"
   ```

7. Follow [the prompts below](#3-answer-the-installation-prompts), keeping the same
   kit/NVMe connected. Repeat the recovery-button sequence whenever requested.
8. After completion, [verify first boot](#4-boot-and-check).

NVIDIA: [Thor ports and buttons][thor-hardware] · [Thor flashing][thor-flash].

## 2B. Install on AGX Orin

Only **P3701-0000 + NVIDIA P3737-0000 carrier**, image
`admiral-jetson-agx-orin.img` matching this bundle's `boards.orin.image` record.
Other AGX SKUs, including 64GB/industrial modules, are not implied. This programs
64 MiB QSPI and NVMe, not Orin eMMC.

1. On the existing kit, personally observe **Secure Boot Disabled** in UEFI or
   `mokutil --sb-state`. Shut down before fitting/changing the NVMe.
2. On the Ubuntu host:

   ```sh
   python3 orin.py check --board orin --bundle-pin "$BUNDLE_PIN"
   ```

   Enter the image's absolute path. Expect `Admiral image: full SHA256, both GPTs
   and partition fingerprint verified.` Resolve host prerequisites using the
   printed apt command after reviewing it, then repeat the check.
3. Connect the host data cable to USB-C **next to the 40-pin header**, not the
   USB-C above the DC jack. Connect the kit's power supply separately.
4. With the kit powered on, hold **Force Recovery**, press/release **Reset**, then
   release Force Recovery.
5. Confirm one NVIDIA/APX endpoint; disconnect other NVIDIA USB devices:

   ```sh
   lsusb -d 0955:
   ```

6. Start installation with the explicit AGX Orin selector:

   ```sh
   sudo /usr/bin/python3 orin.py install --board orin --bundle-pin "$BUNDLE_PIN"
   ```

7. Follow [the prompts below](#3-answer-the-installation-prompts), keeping the same
   kit/NVMe connected. Repeat the recovery-button sequence whenever requested.
8. After completion, [verify first boot](#4-boot-and-check).

NVIDIA: [AGX Orin ports and recovery][orin-hardware] · [Orin flashing][orin-flash].
Existing Orin NX users: see [the separate selector](docs/reference.md#orin-nx).

## 3. Answer the installation prompts

1. Type `I ACCEPT THE RISKS` to continue; this does not authorize an erase.
2. Choose a **new** session directory, e.g.
   `/opt/nvidia-flash-tools/session-thor-1` or `session-orin-1`. It must not exist.
3. Choose a download cache, e.g. `/opt/nvidia-flash-tools/downloads`. Read NVIDIA's
   terms and type `I ACCEPT NVIDIA LICENSE` if accepted. The installer downloads
   and authenticates the pinned BSP/rootfs; cached files are checked too.
4. Enter the matching Admiral image's absolute path.
5. Type `OBSERVED SECURE BOOT DISABLED` only if you personally observed that state
   on this exact kit immediately before the session. Unknown/enabled security or
   unsupported fuses stop installation; do not change security to bypass a refusal.
6. Press Enter when that one kit is in Force Recovery. The tool reads fresh
   identity/security evidence and performs RAM-only NVMe preflight before erase.
7. Review the displayed board, NVMe serial/capacity and approval. Type
   `ERASE FIRMWARE AND NVME EXPERIMENTAL` only for that hardware.
8. Reenter Force Recovery when requested; leave power and USB connected.
9. Review the selected NVMe again. Type `ERASE NVME` to authorize its whole-disk
   write and readback verification. Backup GPT is relocated; filesystems are not grown.

Any other confirmation aborts. Never substitute a host `/dev/nvme...` path or put
this whole-disk image into NVIDIA `APP`/`system.img`. Use a new session for retries;
only the authenticated download cache is reusable.

## 4. Boot and check

1. After verified completion, release recovery buttons/jumpers and power-cycle.
2. Use a connected display or the kit's serial console to confirm Admiral starts
   from NVMe with the expected release and storage.
3. Run the intended GPU/CUDA workload. Disk readback or `nvcc --version` alone
   does not verify GPU execution; `nvidia-smi` is not an Orin requirement.

The session's `first-test-report.json` records
`write-verified-not-boot-qualified`, not a successful-boot result. Keep logs private;
they can contain ECIDs, disk serials and paths. Nothing is uploaded automatically.

## References

- [Troubleshooting, first-boot diagnostics and stock NVIDIA recovery](docs/troubleshooting.md)
- [Authentication, security checks, vendor inputs and prepare-only mode](docs/reference.md)
- [Development, reproducible packaging and offline tests](docs/development.md)
- [Native I/O protocol](NATIVE-PROTOCOL.md)
- [NVIDIA JetPack 7.2.1 / Jetson Linux 39.2.1 downloads][downloads]
- [NVIDIA Quick Start][quickstart]

Project code is proprietary; see [LICENSE](LICENSE). NVIDIA inputs retain their
licenses. Built bundles include [OpenSSL](OPENSSL-LICENSE.txt) and
[musl](MUSL-COPYRIGHT.txt) notices; see the development guide for toolchain details.

[downloads]: https://developer.nvidia.com/embedded/jetpack/downloads/archive-7.2.1
[quickstart]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/IN/QuickStart.html
[thor-hardware]: https://docs.nvidia.com/jetson/agx-thor-devkit/user-guide/latest/hardware_layout.html
[thor-flash]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupportJetsonThor.html
[orin-hardware]: https://docs.nvidia.com/jetson/agx-orin-devkit/user-guide/latest/howto.html
[orin-flash]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupport.html
