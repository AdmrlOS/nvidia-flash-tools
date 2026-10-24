# Development and offline verification

## Layout

```text
thor.py, orin.py, install.py   preserved command-line entrypoints
nvidia_flash_tools/           implementation package
package.py                   reproducible allowlisted archive builder
tests/                       offline tests and fixture helpers
docs/                        usage references, included in the bundle
recovery-io.c, *.c, *.sh      native helper, fixtures and recovery script
release.json                 pinned vendor inputs and board image records
```

Use package imports such as `from nvidia_flash_tools.image import ...`.
`python3 -m nvidia_flash_tools.thor --help` also works. Runtime data and helper
paths are relative to the bundle root, not the implementation directory.
`install.py --help` exposes the lower-level interface; execution requires the
independently authenticated generated release, not raw `release.json`.

## Build

Build on Linux with an AArch64 cross compiler whose target sysroot provides
**static OpenSSL libcrypto, pthread and dl**:

```sh
mkdir -p dist
python3 package.py dist/nvidia-flash-tools.tar.gz --compiler /absolute/path/to/aarch64-linux-musl-gcc
```

The checkout lacks the compiled helper/generated manifests. The builder checks
static AArch64 ELF, embeds real source/helper pins and writes the archive,
adjacent `.sha256` and `.helper`. The archive root is `admiral-jetson-installer/`.
It contains no NVIDIA archives, disk images or private signing keys.

Obtain the manifest pin for independent delivery to recipients:

```sh
tar -xOf dist/nvidia-flash-tools.tar.gz admiral-jetson-installer/engineering-manifest.json | sha256sum
```

Build twice to fresh filenames and compare bytes. Independently verify the archive
and manifest pins after every source, documentation or image-record change; never
reuse an older handoff's pins. Before delivery, extract outside the checkout and
run entrypoint help, bundle authentication and image checks against the actual
supplied board images. Fixture image checks are regression tests, not release
image validation or hardware qualification.

The existing static-helper toolchain uses OpenSSL 3.6.4 and musl 1.2.6. The archive
includes `OPENSSL-LICENSE.txt` and `MUSL-COPYRIGHT.txt`; review/update redistribution
notices if using another toolchain.

## Offline tests

Use Linux, Python 3, GCC, OpenSSL development headers/libcrypto, OpenSSH and GNU
host tools. No pytest or pip dependencies are needed. Use private scratch and
ancestors rather than `/tmp`; tests enforce trusted-path rules:

```sh
umask 077
install -d -m 0700 "$HOME/.cache/nvidia-flash-tools-tests"
export TMPDIR="$HOME/.cache/nvidia-flash-tools-tests"
python3 -m unittest discover -v
```

Vendor-dependent tests skip visibly without separately licensed inputs. Verify
and extract the pinned BSP, then configure:

```sh
export NVIDIA_VENDOR_ROOT=/absolute/path/to/Linux_for_Tegra
export AARCH64_CC=/absolute/path/to/aarch64-linux-musl-gcc
export NVIDIA_PREPARED_BOOT_IMAGE=/absolute/path/to/prepared/bootloader/boot0.img
python3 -m unittest discover -v
```

The default vendor root is `downloads/Linux_for_Tegra`. Explicit missing inputs
fail instead of skipping. The prepared Orin boot image must come from the actual
pinned recovery-initrd preparation flow, including its generated SSH host key and
utilities, not an arbitrary stock boot image. Do not invent EEPROM/security
fixtures. Tests exercise real vendor methods, ordinary files, local sockets,
compiled native fixtures and mocked hardware edges; report skips separately.
See [the native protocol](../NATIVE-PROTOCOL.md) for retained-descriptor I/O.
