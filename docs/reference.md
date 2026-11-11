# Installer reference

Start with [installation](../README.md). These details explain the inputs and
checks, not additional steps needed for the guided installation.

## Authentication and security

Authenticate the archive before running its Python. A checksum from the same
untrusted download source is not an independent trust root. The archive pin
identifies the compressed archive; `--bundle-pin` identifies the exact bytes of
`engineering-manifest.json`. Every rebuild can change both pins.

The manifest authenticates allowlisted source/documentation files, the native
helper and the generated release. Schema 1 accepts relative nested package paths
as well as flat artifact names. Absolute paths, traversal and symlinked artifact
paths are refused. The extracted installation/session paths must have trusted,
non-writable ancestors; privileged operations use a fresh private workspace.
Authentication cannot protect Python already executed from an untrusted archive.

The guided flow requires current, personally observed Secure Boot Disabled on
this same kit. Fresh silicon, EEPROM and fuse evidence establish the exact
module/carrier/SKU and supported security state. Unknown evidence stops without
fallback targeting. No fuse burning, security disabling or key enrollment occurs.
The release is classified `engineering-test-keys`, not production trust.

RAM-only first contact checks board and NVMe identity before persistent erase.
Each destructive approval is bound to the release, installer, helper, recovery
payload, generated firmware package, board identity and disk identity. Firmware
programming uses validated targets and readback; NVMe writes retain an exclusive
native descriptor, verify data/GPT and relocate the backup GPT. The installer
does not resize filesystems. USB enumeration alone does not prove board identity.

## NVIDIA inputs

The guided tool downloads separately licensed NVIDIA inputs only after license
consent, verifies lengths/SHA256s and rechecks cached files:

| Input | Filename |
| --- | --- |
| Driver BSP | `Jetson_Linux_R39.2.1_aarch64.tbz2` |
| Sample rootfs | `Tegra_Linux_Sample-Root-Filesystem_R39.2.1_aarch64.tbz2` |

Exact URLs and pins are in `release.json`; generated `engineering-release.json`
contains the helper identity. To inspect the authenticated release:

```sh
python3 -m json.tool engineering-release.json
```

Use the [official downloads](https://developer.nvidia.com/embedded/jetpack/downloads/archive-7.2.1).
Do not select “latest”. The bundle contains neither NVIDIA archives nor Admiral
disk images and does not automatically download an Admiral image.

## Prepare without device writes

From the authenticated root-owned extraction, choose one:

```sh
sudo /usr/bin/python3 thor.py prepare --bundle-pin "$BUNDLE_PIN"
```

```sh
sudo /usr/bin/python3 orin.py prepare --board orin --bundle-pin "$BUNDLE_PIN"
```

`prepare` downloads/prepares vendor tools without device writes. It does not
generate a board-identity-approved flash package. `install` needs its own new
session; reuse only the download cache.

## Orin NX

The separate `orin.py --board orin-nx` selector accepts only P3767-0000 /
P3768-0000, the stock Super DTB and `admiral-orin-nx.img` matching the release
record. Its NVIDIA configuration is `jetson-orin-nano-devkit-super`, not AGX Orin.
Use the exact carrier's NVIDIA recovery-jumper instructions, not AGX buttons.
Image authentication, security observation and both erase confirmations apply.

```sh
python3 orin.py check --board orin-nx --bundle-pin "$BUNDLE_PIN"
sudo /usr/bin/python3 orin.py install --board orin-nx --bundle-pin "$BUNDLE_PIN"
```

## reComputer J40/J4012 {#recomputer-j40}

`orin.py --board recomputer-j40` accepts only a Seeed reComputer J4012: a
P3767-0000 (Orin NX 16GB) module on Seeed's J401 carrier and
`admiral-recomputer-j40.img` matching the release record. Its flash configuration
is `recomputer-j40-qspi` (installed from the bundle, not an NVIDIA name). Module
SKUs 3767-0001/0003/0004 (J4011, J3011, J3010), other modules and any NVIDIA
carrier are refused. Security observation and both erase confirmations apply.

```sh
python3 orin.py check --board recomputer-j40 --bundle-pin "$BUNDLE_PIN"
sudo /usr/bin/python3 orin.py install --board recomputer-j40 --bundle-pin "$BUNDLE_PIN"
```

### Carrier rule

Seeed zeroes `cvb_eeprom_read_size`, and the J401 schematic shows an AT24C02
board-ID EEPROM on I2C2 rather than the NVIDIA carrier EEPROM, so the exact
`cvb == 3768-0000` rule cannot identify it. One reComputer J4012 (R35.2.1 QSPI as
received) answered a manual R39.2.1 `dump eeprom cvb` with MB2
`NV3P_SERVER: Could not read eeprom for module cvb.`, the `dump-failed` outcome.
The rule (`nvidia_flash_tools/carrier.py`, rule id
`recomputer-j40-cvb-v2`) is:

1. The module (`cvm`) decode must equal `3767-0000` exactly, and the fuse/security
   checks are those of orin-nx. Anything else stops.
2. The carrier EEPROM is dumped after the fuse and module reads, by a separate
   `tegraflash` invocation whose failure is tolerated, then decoded with
   `chkbdinfo -i/-k`. Only that dump and decode may fail without ending the
   session's authority. A failed dump stops `tegraflash` before its recovery
   reboot and leaves the MB2 applet running (the boot ROM no longer answers).
   Each `tegraflash` run deletes its private session state, so no later run can
   reset the applet: the installer asks the operator to power-cycle into Force
   Recovery, then requires the same boot ROM identity.
3. The result is classified by the single table below, in this order, and recorded
   verbatim in the board identity: cvb sha256 and size, the dump's return code, each
   decoder's return code/output, the outcome, and the dump output tail (the tail
   contains timestamps, so it is excluded from the same-board re-probe comparison
   only).
4. Only accepted outcomes continue. The operator must then type
   `OBSERVED SEEED RECOMPUTER J401 CARRIER` at the identity stage, before RAM boot.
5. The evidence and the typed phrase are part of the `physical_board` identity in
   both destructive approvals, so the approval digests change if either differs. The
   approval is refused without both. Between stages the re-probe must give identical
   evidence.

| Outcome | Accepted | Meaning |
| --- | --- | --- |
| `dump-failed` | yes | no file, and MB2 answered `NV3P_SERVER: Could not read eeprom for module cvb.` (nothing at NVIDIA's carrier EEPROM address); the exact return code and output are recorded |
| `dump-error` | no | `dump eeprom cvb` exited non-zero or wrote no file without that MB2 answer (tool, USB or applet error). NVIDIA's own retry through `tegradevflash` always fails on `Invalid option --chip`; that line is never evidence |
| `unexpected-size` | no | dump succeeded but the output is not a regular single-link 256-byte file |
| `nvidia-carrier-decoded` | no | `chkbdinfo -i` or `-k` returned a 4-digit NVIDIA board id/SKU; includes 3768, 3509, 3737, 4071 |
| `blank-zero` | yes | 256 bytes of 0x00 and neither decoder returned a value |
| `blank-ff` | yes | 256 bytes of 0xff and neither decoder returned a value |
| `undecodable` | yes | 256 bytes, not silently blank, and no decoder returned a 4-digit id/SKU; any decoder text is recorded |

The table is `CVB_TABLE` in `carrier.py` and is exercised exhaustively by
`tests/test_orin_j40.py`. To tighten it after a real capture, remove outcomes from
`CVB_TABLE` or add the captured cvb sha256 to `PINNED_CVB_SHA256` (then `undecodable`
must match it), update this table and the tests, and rebuild. Never loosen it from
documentation alone.

### Vendor inputs

`vendor-inputs/recomputer-j40/` holds files copied from the Admiral BSP
(`staging/bsp-ci`, commits `a551088`, `73e3a23`): the MB2 patch, `recomputer-j40-qspi.conf`,
the four J401 DTBs and the IMX219 dual overlay. `release.json` pins their sizes and
SHA256s and the manifest authenticates them like other bundle files. After the pinned
NVIDIA BSP is extracted into the fresh private workspace, the installer verifies the
stock `tegra234-mb2-bct-common.dtsi` SHA256 (`42572d28...`), applies exactly the pinned
patch (`cvb_eeprom_read_size <0x100>` to `<0>`, no fuzz), verifies the patched SHA256
(`42f96bb9...`), then installs the configuration at the tree root and the DTBs/DTBO
under `kernel/dtb/`. The workspace graph is resealed, so these bytes are part of every
later approval. Signing, planning, SPI readback and the NVMe write are unchanged,
including the `BootOrderNvme.dtbo` overlay.

## Advantech MIC-733-AO {#mic-733-ao}

`orin.py --board mic-733-ao` accepts only an Advantech MIC-733-AO6A1: a
P3701-0005 (AGX Orin 64GB) module on Advantech's MIC-733 carrier and the image
named by the `boards.mic-733-ao.image` record (a full-disk image of the shared
`nvidia-tegra234` target whose boot slots carry the
`tegra234-mic-733-ao+p3701-0005.dtb` board DTB). Its flash configuration is
`mic-733-ao-qspi` (installed from the bundle, not an NVIDIA name). Module SKUs
3701-0000/0004 (32GB), other modules and any NVIDIA carrier are refused, even
though the flash recipe carries their DTBs: the image boots the 0005 DTB only.
Security observation and both erase confirmations apply. Recovery USB:
`0955:7023` (AGX Orin 64GB), entered with the SW_REC1/SW_RST1 buttons; `7020`
is the booted OS.

```sh
python3 orin.py check --board mic-733-ao --bundle-pin "$BUNDLE_PIN"
sudo /usr/bin/python3 orin.py install --board mic-733-ao --bundle-pin "$BUNDLE_PIN"
```

**Image pin.** The release record pins the final staging lab image's size and
SHA256 (`admiral-nvidia-tegra234-advantech-mic-733-ao-staging.img`, the shared
nvidia-tegra234 image with the MIC-733-AO `board.dtb` and staging endpoints).
A record with `"size": null, "sha256": null` is refused by `check`/`install`
(`no size/SHA256 pinned`); a new image needs new pins and a bundle rebuild.

### Carrier rule (`mic-733-ao-cvb-v2`)

Advantech's MB2 BCT sets `cvb_eeprom_read_size = 0`: there is no EEPROM at I2C0
0xac and with NVIDIA's default MB2 busy-spins in "Prepare eeprom data". The rule
(`nvidia_flash_tools/carrier.py`, `RULES['mic-733-ao']`) works like the J401 rule:

1. The module (`cvm`) decode must equal `3701-0005` exactly; fuse/security checks
   are those of the NVIDIA kits.
2. Fuses and module EEPROM are read first, ending with their own recovery reboot.
   The carrier EEPROM is dumped last by a separate, time-bounded (180 s)
   `tegraflash` run whose failure is tolerated, then decoded with `chkbdinfo -i/-k`.
   A dump that does not return within the bound stops the probe. If MB2 answers
   `Could not read eeprom for module cvb` the applet keeps running and the operator
   re-enters Force Recovery (hold SW_REC1, press and release SW_RST1, release
   SW_REC1); the installer then requires the same boot ROM identity.
3. The result is classified by the outcome table in [the J401 section](#recomputer-j40) and
   recorded verbatim. Accepted for this board (`MIC733_ACCEPTED`): `dump-failed`
   only. Refused: every other outcome, including `dump-error`,
   `unexpected-size`, `blank-zero`, `blank-ff`, `undecodable` and
   `nvidia-carrier-decoded` (any 4-digit id, including 3737, 3711, 3740).
4. The operator types `OBSERVED ADVANTECH MIC-733-AO CARRIER` at the identity
   stage. Evidence and phrase are part of `physical_board` in both approvals; a
   J401 record or phrase never satisfies this rule.

**Captured.** The first RAM-only probe of a real MIC-733-AO6A1 (R39.2.1) read
module `3701-0005`, all security/ODM fuse words zero, and the carrier dump ended
`dump-failed` with MB2's `Could not read eeprom for module cvb` answer; the
applet stayed running and one SW_REC1 + SW_RST1 re-entry was needed. Rule v1
accepted four outcomes provisionally; v2 accepts only the captured one. Never
loosen it from documentation alone.

### QSPI geometry

The installer writes and reads back the whole 64 MiB controller and accepts an
`mtd0` erase size of 4 KiB (measured on a J4012) or 64 KiB. The AGX Orin
P3701-0005 module's value has not been measured. For `mic-733-ao` the RAM recovery
reads `/sys/class/mtd/mtd0/{name,type,size,erasesize,writesize}` read-only before
the firmware approval, prints them, binds them into both approvals
(`firmware_package.qspi_geometry`) and stops on an unaccepted value before the
operator approves anything. Once measured, record the value here.

### Vendor inputs {#mic-733-ao-vendor-inputs}

`vendor-inputs/mic-733-ao/` holds the Admiral BSP's MIC-733-AO flash recipe
(`staging/bsp-ci` `c2fecbe`, `board/admiral/boards/mic-733-ao/flash/`) and the three
per-SKU DTBs from the shared `nvidia-tegra234` kernel build at that commit
(`generic-dtbs`, byte-identical to `images/nvidia/`). Their carrier deltas come
from Advantech's kernel DTB as published by Avocado Linux
(`avocado-linux/bsp-mic-733-ao5a1`, `stone/carrier-bsp/tegra234-p3737-0000+p3701-0000-nv-adv.dtb`). After the NVIDIA BSP is extracted into the fresh
workspace, the installer checks the SHA256 of the NVIDIA files the configuration
derives from (the BSP `flash-qspi.sh` `NVIDIA_SHA` set), creates the two
`-mic-733-ao` MB1 files from NVIDIA's a04 pinmux/GPIO files with the pinned patch
(stock and result SHA256 checked), and installs the MB2 misc BCT, the QSPI and
recovery configurations and the DTBs. NVIDIA's own files are not modified. ODMDATA
is `gbe-uphy-config-0,hsstp-lane-map-3,nvhs-uphy-config-0,hsio-uphy-config-16`.
