# Advantech MIC-733-AO vendor inputs

Copied unmodified from the Admiral BSP (`staging/bsp-ci`, commit `c2fecbe`,
`board/admiral/boards/mic-733-ao/flash/`, tree `23dae5d`) and the shared
`nvidia-tegra234` kernel build output at that commit
(`build/nvidia-l4t-kernel-oot-39.2.1/build/nvidia-public/devicetree/generic-dtbs/`,
byte-identical to `images/nvidia/`). Every byte
is pinned by size and SHA256 in `release.json`
(`boards.mic-733-ao.vendor_inputs`) and authenticated by the engineering
manifest like the other bundle files. `nvidia_flash_tools/vendor_inputs.py`
installs them into the fresh private workspace only, the way the BSP's
`flash-qspi.sh` installs them into a Linux_for_Tegra tree. NVIDIA's own files
are never modified.

| File | Installed as |
| --- | --- |
| `mic-733-ao-qspi.conf` | `Linux_for_Tegra/mic-733-ao-qspi.conf` (the `flash.sh` board name) |
| `mic-733-ao-recovery.conf` | `Linux_for_Tegra/mic-733-ao-recovery.conf` (RAM-boot `recovery.img` only; written for nvidia-flash-tools, not from the BSP) |
| `bct/tegra234-mb2-bct-misc-p3701-0000-mic-733-ao.dts` | `bootloader/generic/BCT/` (MB2 BCT with `cvb_eeprom_read_size = <0x0>`) |
| `patches/0001-mb1-pinmux-gpio-mic-733-ao.patch` | applied to copies of NVIDIA's `tegra234-mb1-bct-{gpio,pinmux}-p3701-0000-a04.dtsi`, creating the `-mic-733-ao.dtsi` files (stock and result SHA256 pinned) |
| `dtb/tegra234-mic-733-ao+p3701-000{0,4,5}.dtb` | `kernel/dtb/` |
| `sample-rootfs-members.txt` | not installed: the traced NVIDIA sample-rootfs subset extracted for this board |

Before installing, the installer checks the SHA256 of the NVIDIA R39.2.1 files
the configuration derives from (`p3737-0000-p3701-0000.conf`,
`p3701.conf.common`, the a04 pad-voltage file, `tegra234-mb2-bct-common.dtsi`
and both a04 MB1 sources; the values of `flash-qspi.sh` `NVIDIA_SHA`), so a
tree that another board's recipe already patched is refused.

The configuration, BCT and patch derive from NVIDIA BSD-3-Clause files; the
NVIDIA notice in their headers applies. The DTBs are compiled from NVIDIA's
R39.2.1 device-tree sources plus the BSP's MIC-733-AO carrier `.dtsi`. The
carrier deltas in it (pinmux, PCIe, GPIO expanders, HDMI DCB, HDMI hot-plug
GPIO and the C4 `advantech,disable-aspm-l1-after-retrain` property) come from
Advantech's kernel DTB as published by Avocado Linux
(`avocado-linux/bsp-mic-733-ao5a1`,
`stone/carrier-bsp/tegra234-p3737-0000+p3701-0000-nv-adv.dtb`, git blob
`399400c0`). The HDMI DCB is byte-identical to that DTB's
`display@13800000` and to the running device tree of a MIC-733-AO6A1. Refreshing means copying new BSP
outputs here, running `scripts/pin-mic733-inputs.py`, and rebuilding the bundle
(new archive and manifest pins).
