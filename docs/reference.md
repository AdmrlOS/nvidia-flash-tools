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
