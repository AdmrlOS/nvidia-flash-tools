# NVIDIA flash tools

Install an Admiral disk image on a **Jetson AGX Thor**, **Jetson AGX Orin**,
Orin NX reference kit, **Seeed reComputer J4012** or **Advantech MIC-733-AO**
using the pinned NVIDIA Jetson Linux 39.2.1 recovery tools.

**Back up first: installation replaces QSPI boot firmware and erases the entire
selected NVMe.** Keep stable power and disable host sleep. Secure Boot must already be disabled; the installer
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

## 2C. Install on reComputer J40/J4012

Only a **Seeed reComputer J4012** (Jetson Orin NX 16GB, **P3767-0000**) on Seeed's
**J401** carrier, image `admiral-recomputer-j40.img` matching this bundle's
`boards.recomputer-j40.image` record. J4011 (NX 8GB), J3010/J3011 (Nano) and any
other module SKU are refused. This programs the 64 MiB QSPI with the J401
settings (HDMI pinmux, Seeed device trees, MB2 carrier-EEPROM read disabled; all
pinned in `vendor-inputs/recomputer-j40/`) and the whole NVMe, not eMMC.

The J401 has no NVIDIA-format carrier EEPROM, so the carrier cannot be proven from
EEPROM data. The module (`3767-0000`), fuses and Secure Boot checks are exactly as
strict as Orin NX. The carrier EEPROM result is recorded in the approval and must
not decode as any NVIDIA carrier (3768, 3509, 3737, 4071 ...); you must also type a
confirmation that you observed the Seeed unit ([rule](docs/reference.md#recomputer-j40)).

1. On the existing unit, personally observe **Secure Boot Disabled** in UEFI or
   `mokutil --sb-state`. Shut down before fitting/changing the NVMe (M.2 Key M).
2. On the Ubuntu host:

   ```sh
   python3 orin.py check --board recomputer-j40 --bundle-pin "$BUNDLE_PIN"
   ```

   Enter the image's absolute path. Expect `Admiral image: full SHA256, both GPTs
   and partition fingerprint verified.` Resolve host prerequisites using the
   printed apt command after reviewing it, then repeat the check.
3. Recovery wiring, per [Seeed's flashing guide][seeed-flash]: connect the host's
   USB data cable to the J401's single **USB Type-C** port (device mode). On the
   12-pin button header use a jumper wire to bridge **FC REC** (pin 3) and **GND**
   (pin 2 or 4); pin 1 is PWR BTN, pin 5 SYS RET. Then connect the power adapter
   to the reComputer.
4. Confirm exactly one NVIDIA/APX endpoint; disconnect other NVIDIA USB devices:

   ```sh
   lsusb -d 0955:
   ```

   Seeed lists `0955:7323 NVidia Corp` for the Orin NX 16GB (`7423` NX 8GB, `7523`
   Nano 8GB, `7623` Nano 4GB; those modules are refused later by the exact
   module-identity check, not by this product ID). Leave the jumper fitted until
   the installer completes. Whenever it asks you to re-enter Force Recovery,
   power-cycle the unit (jumper still fitted) and press Enter; the installer
   then waits for the board to enumerate again on the same USB port. Expect two
   power cycles: one after the carrier check (the J401 has no NVIDIA carrier
   EEPROM, and NVIDIA's tool leaves its flashing applet running after that
   read) and one after the firmware stage.
5. Start installation with the explicit selector:

   ```sh
   sudo /usr/bin/python3 orin.py install --board recomputer-j40 --bundle-pin "$BUNDLE_PIN"
   ```

6. Follow [the prompts below](#3-answer-the-installation-prompts), including the
   extra carrier confirmation (`OBSERVED SEEED RECOMPUTER J401 CARRIER`, typed only
   after reviewing the printed carrier evidence), keeping the same unit/NVMe connected.
7. After completion, [verify first boot](#4-boot-and-check).

To capture only the carrier evidence on first contact, answer anything else at the
carrier confirmation prompt: the tool has then done only RAM-only fuse/EEPROM reads
and stops before RAM boot, any erase or any write.

Seeed: [reComputer J4012 flash guide](https://wiki.seeedstudio.com/reComputer_J4012_Flash_Jetpack/).

## 2D. Install on Advantech MIC-733-AO

Only an **Advantech MIC-733-AO6A1** (Jetson AGX Orin 64GB, module **P3701-0005**)
on Advantech's own MIC-733 carrier, image
`admiral-nvidia-tegra234-advantech-mic-733-ao-staging.img` matching this bundle's
`boards.mic-733-ao.image` record (the image boots the P3701-0005 device tree).
Other module SKUs (including the 32GB MIC-733-AO5A1) and any NVIDIA carrier are
refused. This programs the 64 MiB QSPI with the MIC-733-AO boot firmware
(Advantech's MB1 pinmux/GPIO changes, the MB2 BCT with the carrier-EEPROM read
disabled, the carrier UPHY mapping in ODMDATA and the MIC-733-AO device trees;
all pinned in `vendor-inputs/mic-733-ao/`) and the whole NVMe. The eMMC, which
holds the stock Advantech OS, is not written, but once QSPI holds the R39.2.1
firmware that stock (L4T R36) OS no longer boots; reflash it with Advantech's
tools to go back.

The MIC-733 carrier has no NVIDIA-format carrier EEPROM, so the carrier cannot be
proven from EEPROM data. The module (`3701-0005`), fuses and Secure Boot checks
are as strict as for NVIDIA kits. The carrier EEPROM result is recorded in the
approval and must not decode as any NVIDIA carrier (3737, 3711, 3740 ...); you also
type a confirmation that you observed the Advantech unit
([rule](docs/reference.md#mic-733-ao)).

1. On the existing unit, personally observe **Secure Boot Disabled** in UEFI
   setup (Device Manager > Secure Boot Configuration) or `mokutil --sb-state` on
   the stock OS. Shut down before fitting/changing the NVMe (M.2 2280 Key M).
2. On the Ubuntu host:

   ```sh
   python3 orin.py check --board mic-733-ao --bundle-pin "$BUNDLE_PIN"
   ```

   Enter the image's absolute path. Expect `Admiral image: full SHA256, both GPTs
   and partition fingerprint verified.` Resolve host prerequisites using the
   printed apt command after reviewing it, then repeat the check.
3. Connect the host's USB data cable to the MIC-733-AO's **recovery (device-mode)
   USB port** (see Advantech's MIC-733-AO user manual for its position) and keep
   the unit's power supply connected.
4. Enter Force Recovery with the two buttons: with the unit powered,
   **hold the recovery button SW_REC1, press and release the reset button
   SW_RST1, then release SW_REC1**.
5. Confirm exactly one NVIDIA/APX endpoint; disconnect other NVIDIA USB devices:

   ```sh
   lsusb -d 0955:
   ```

   Expect `0955:7023` (AGX Orin 64GB in Force Recovery). `0955:7020` means the
   stock OS booted instead: repeat step 4. Whenever the installer asks you to
   re-enter Force Recovery, repeat step 4 and press Enter; the installer then waits
   for the board to enumerate again on the same USB port. Expect up to two
   re-entries: one after the carrier check (if NVIDIA's tool leaves its flashing
   applet running after that read, as on other carriers without the EEPROM) and
   one after the firmware stage.
6. Start installation with the explicit selector:

   ```sh
   sudo /usr/bin/python3 orin.py install --board mic-733-ao --bundle-pin "$BUNDLE_PIN"
   ```

7. Follow [the prompts below](#3-answer-the-installation-prompts), including the
   extra carrier confirmation (`OBSERVED ADVANTECH MIC-733-AO CARRIER`, typed only
   after reviewing the printed carrier evidence), keeping the same unit/NVMe connected.
   Before the firmware approval the tool also prints the QSPI geometry it measured
   in RAM recovery (`QSPI mtd0 measured in RAM recovery: ...`).
8. After completion, [verify first boot](#4-boot-and-check).

To capture only the carrier evidence on first contact, answer anything else at the
carrier confirmation prompt: the tool has then done only RAM-only fuse/EEPROM reads
and stops before RAM boot, any erase or any write.

## 3. Answer the installation prompts

1. Type `I ACCEPT THE RISKS` to continue; this does not authorize an erase.
2. Choose a **new** session directory, e.g.
   `/opt/nvidia-flash-tools/session-thor-1`, `session-orin-1`, `session-j40-1` or
   `session-mic733-1`. It must not exist.
3. Choose a download cache, e.g. `/opt/nvidia-flash-tools/downloads`. Read NVIDIA's
   terms and type `I ACCEPT NVIDIA LICENSE` if accepted. The installer downloads
   and authenticates the pinned BSP/rootfs; cached files are checked too.
4. Enter the matching Admiral image's absolute path.
5. Type `OBSERVED SECURE BOOT DISABLED` only if you personally observed that state
   on this exact kit immediately before the session. Unknown/enabled security or
   unsupported fuses stop installation; do not change security to bypass a refusal.
6. Press Enter when that one kit is in Force Recovery. The tool reads fresh
   identity/security evidence and performs RAM-only NVMe preflight before erase.
   **reComputer J40/J4012 only:** the tool then prints the module decode and the
   recorded carrier EEPROM (`cvb`) outcome (sha256 and decoded fields, or the exact
   dump failure). If the outcome is refused it stops. Type
   `OBSERVED SEEED RECOMPUTER J401 CARRIER` only if the unit in front of you is a
   Seeed reComputer J40/J4012 with its original carrier; anything else aborts. The
   evidence and this confirmation are part of the approval you review next.
   **Advantech MIC-733-AO only:** the same carrier evidence is printed; type
   `OBSERVED ADVANTECH MIC-733-AO CARRIER` only if the unit in front of you is an
   Advantech MIC-733-AO with its original carrier.
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

[seeed-flash]: https://wiki.seeedstudio.com/reComputer_J4012_Flash_Jetpack/
[downloads]: https://developer.nvidia.com/embedded/jetpack/downloads/archive-7.2.1
[quickstart]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/IN/QuickStart.html
[thor-hardware]: https://docs.nvidia.com/jetson/agx-thor-devkit/user-guide/latest/hardware_layout.html
[thor-flash]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupportJetsonThor.html
[orin-hardware]: https://docs.nvidia.com/jetson/agx-orin-devkit/user-guide/latest/howto.html
[orin-flash]: https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupport.html
