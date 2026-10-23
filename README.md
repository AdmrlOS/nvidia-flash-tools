# NVIDIA flash tools

**Not tested on physical devices.** USB recovery, firmware acceptance, first boot,
CUDA and interruption recovery remain unverified. A verified write is not proof
of successful boot. Back up all data before using this software.

This Ubuntu host installer prepares pinned NVIDIA recovery software, replaces
validated QSPI boot firmware, and writes a matching Admiral whole-disk image to
the selected kit's NVMe. **QSPI replacement and complete NVMe erasure are
destructive.** Power loss or failure can require stock NVIDIA recovery. No fuse
burning, key enrollment or security disabling is performed or authorized.
UEFI Secure Boot must be **already disabled**, personally observed on the same
kit before recovery. Enabled, unknown or incompatible fuse policy stops the
installer; never change security to bypass a refusal.

## Supported combinations

| Selector | Module | NVIDIA reference carrier |
| --- | --- | --- |
| Thor (`thor.py`) | P3834-0008 | P4071-0000 |
| AGX Orin (`orin.py --board orin`) | P3701-0000 | P3737-0000 |
| Orin NX 16GB (`orin.py --board orin-nx`) | P3767-0000 | P3768-0000, stock Super DTB |

No other SKU/carrier is supported. AGX Orin eMMC is not a firmware target; only
its validated 64MiB QSPI is programmed. NVMe requires one selected namespace with
512-byte logical sectors. These are implemented targets, not hardware-tested
claims. The image is written as a disk, never nested in an NVIDIA APP partition.

## Host and USB preparation

Use a separate physical **Ubuntu 22.04 or 24.04 x86_64 PC**, at least 40 GiB free,
stable mains power on both systems, sleep disabled and a direct USB data cable.
VMs, WSL and containers are refused. Disconnect other NVIDIA USB devices. Missing
Ubuntu packages and an apt command are printed for review; the installer never
installs packages or escalates privileges automatically.

Observe Secure Boot Disabled in this kit's UEFI menu or run `mokutil --sb-state`
on its current OS immediately before recovery. This does not replace fresh
EEPROM, UID and fuse checks. Unknown state is a stop.

* **Thor:** recovery USB-C beside HDMI; power uses the other USB-C. Powered off:
  hold Force Recovery, press/release Power, release Force Recovery. Powered on:
  hold Force Recovery, press/release Reset, release Force Recovery.
* **AGX Orin:** use its documented recovery USB-C port. Hold Force Recovery,
  press/release Reset while powered (or apply power), release Force Recovery.
* **Orin NX / P3768:** disconnect power, connect documented FC REC and GND on J14
  pins 9 and 10, connect recovery USB-C, apply power, then remove the jumper.
  Confirm orientation against the NVIDIA carrier manual; never short unknown
  pins. Power off and repeat when recovery reentry is requested.

Keep the **same kit and NVMe** connected throughout; reenter recovery when asked.
Fresh identity is checked at transitions, including RAM-only recovery/NVMe
preflight before persistent erase. Unknown identity or generated layouts stop.

## Authenticate and run a built archive

Obtain a built archive from the release operator (a GitHub release attachment
when published), **independently supplied archive and bundle-manifest SHA256s**,
and the separately supplied matching Admiral image. No authenticated public image
URL is configured. `release.json` lists exact image names, sizes and hashes.
NVIDIA BSP/rootfs downloads are separate, pinned and subject to NVIDIA's terms;
license/download consent is requested before fetching them.

Verify the archive **before extracting or running its Python**. A self-computed
hash from an untrusted download is not a trust root. Substitute independently
received values below. Extract into a new root-owned location with ancestors
that are not group/other writable. Do not reuse an existing extraction directory.

```sh
printf '%s  %s\n' ARCHIVE_SHA256 nvidia-flash-tools.tar.gz | sha256sum -c -
sudo install -d -m 0755 /opt/nvidia-flash-tools
sudo tar -xzf nvidia-flash-tools.tar.gz -C /opt/nvidia-flash-tools
cd /opt/nvidia-flash-tools/admiral-jetson-installer

# Offline image check or preparation without device writes:
python3 thor.py check --bundle-pin BUNDLE_PIN
sudo /usr/bin/python3 thor.py prepare --bundle-pin BUNDLE_PIN

# Choose ONE exact kit to flash:
sudo /usr/bin/python3 thor.py install --bundle-pin BUNDLE_PIN
sudo /usr/bin/python3 orin.py install --board orin --bundle-pin BUNDLE_PIN
sudo /usr/bin/python3 orin.py install --board orin-nx --bundle-pin BUNDLE_PIN
```

`BUNDLE_PIN` is the independent `engineering-manifest.json` SHA256. Orin also
accepts `check` and `prepare`. Prompts request a new private session directory
and download cache under trusted root-owned parents, plus the matching image.
Accept the untested-software risks explicitly. Review the exact board, disk and
digest-bound approval: firmware replacement requires
`ERASE FIRMWARE AND NVME EXPERIMENTAL`, then a separate `ERASE NVME` confirmation.
Other answers abort. Firmware has full-range readback; disk writing retains an
exclusive descriptor and verifies image/GPT data. No prior qualification record
is fabricated or required.

## Build from source

Python uses the standard library; no pip dependencies. The checkout alone is
**not** a guided executable bundle: it lacks the compiled recovery helper and
generated authenticated manifests. Build an archive first:

```sh
mkdir -p dist
python3 package.py dist/nvidia-flash-tools.tar.gz --compiler /absolute/path/to/aarch64-linux-musl-gcc
```

Build on Linux with an **AArch64 cross compiler and static OpenSSL libcrypto,
pthread and dl in its target sysroot**. A bare compiler without these libraries
is insufficient. `package.py` checks AArch64 ELF and absence of a dynamic
interpreter, embeds the actual helper, and generates `engineering-manifest.json`
and `engineering-release.json` with real source/binary pins. It also writes an
archive checksum and adjacent `.helper` output. Build twice to fresh output names
to check reproducibility. Distribute the archive and independent archive/manifest
pins, not the unbuilt checkout. Build outputs are excluded from git; no NVIDIA
assets or Admiral disk images are bundled.

Advanced `install.py` accepts an independently authenticated release manifest;
raw `release.json` lacks generated helper records needed for execution. Authenticate
Python before invoking it: its checks cannot authenticate already-executed bootstrap
code retroactively.

## Tests (no hardware)

Run on Linux with Python 3, GCC, OpenSSL development headers/libcrypto, OpenSSH
and ordinary GNU host tools. Tests compile native fixtures and use ordinary files,
local sockets/pipes and mocked hardware boundaries, not physical devices. No pytest:

Use an owned private `TMPDIR` with non-group/other-writable ancestors (not `/tmp`);
workspace trust checks deliberately reject writable ancestors. For example, under
a private home directory:

```sh
install -d -m 0700 "$HOME/.cache/nvidia-flash-tools-tests"
export TMPDIR="$HOME/.cache/nvidia-flash-tools-tests"
python3 -m unittest discover -v
```

Vendor-dependent tests explicitly skip when separately licensed inputs are absent.
For the full suite, separately download and verify the **39.2.1** driver archive
using the URL, size and SHA256 in `release.json`, extract it, and configure:

```sh
export NVIDIA_VENDOR_ROOT=/absolute/path/to/Linux_for_Tegra
export AARCH64_CC=/absolute/path/to/aarch64-linux-musl-gcc
export NVIDIA_PREPARED_BOOT_IMAGE=/absolute/path/to/prepared/bootloader/boot0.img
python3 -m unittest discover -v
```

`NVIDIA_VENDOR_ROOT` defaults to `downloads/Linux_for_Tegra`. Selected source tests
also enforce file pins. Explicitly configured missing inputs fail, not skip.
`AARCH64_CC` enables the real static-package reproducibility test.
`NVIDIA_PREPARED_BOOT_IMAGE` enables one test of an actual prepared Orin recovery
boot image with generated SSH host key and required tools. It must come from the
pinned vendor recovery-initrd preparation flow; an arbitrary stock boot image or
merely extracted BSP is insufficient. Without it that test skips. Never obtain
fixtures by flashing hardware or inventing EEPROM/security evidence. Report run
and skipped counts: offline success is not physical-device validation.

## Stock recovery, trust and privacy

On failure preserve the private session and STOP message. Do not bypass checks or
blindly retry writes. Restore stable power, enter Force Recovery, and use a fresh
stock NVIDIA BSP/rootfs for the exact kit, not a modified installation workspace.
Stock recovery can erase firmware/eMMC/NVMe too. For Thor, extract the authentic
driver archive and matching sample rootfs under `Linux_for_Tegra/rootfs`, run
`sudo ./apply_binaries.sh`, then use the documented stock command from
`Linux_for_Tegra` after entering recovery:

```sh
sudo ./l4t_initrd_flash.sh --erase-all jetson-agx-thor-devkit internal
```

For Orin follow NVIDIA's exact-module/carrier recovery instructions; do not
substitute Thor commands or another carrier configuration. Consult:

* https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/IN/QuickStart.html
* https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupportJetsonThor.html
* https://docs.nvidia.com/jetson/agx-thor-devkit/user-guide/latest/hardware_layout.html

Machine-readable test-key/unqualified classifications remain trust restrictions,
not release authorization. No private signing keys are shipped. Image-internal
test signatures do not imply firmware Secure Boot acceptance. Technical validation
includes authenticated private workspaces, selected-USB identity binding, exact
signed-package graph validation, QSPI transformation/readback and retained-FD disk
I/O. See [NATIVE-PROTOCOL.md](NATIVE-PROTOCOL.md) and the regression tests for limits.

Logs may include ECIDs, NVMe serials and local paths. Keep them private; share only
reviewed/redacted excerpts. `first-test-report.json` contains status/error type
without identifiers; review it too. No automatic upload occurs. Independently
check first boot, storage, GPU driver and CUDA after a verified write.

## Licensing

Project code is proprietary; see [LICENSE](LICENSE). NVIDIA downloads retain their
own licenses/notices and are not relicensed or redistributed here. The supplied
static-helper build uses OpenSSL 3.6.4 and musl 1.2.6; their notices are preserved
in `OPENSSL-LICENSE.txt` and `MUSL-COPYRIGHT.txt` and included in built archives.
For a different toolchain, review its dependency licenses and update the binary
release notices accordingly.
