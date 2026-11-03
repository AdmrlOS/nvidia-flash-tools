# reComputer J40/J4012 vendor inputs

Copied unmodified from the Admiral BSP (`staging/bsp-ci`, commits `a551088`,
`73e3a23` and `72fdcc6`), `board/admiral/boards/recomputer-j40/flash/` and the
`output/recomputer-j40/images/recomputer-j40-flash/{dtb,dtbo}` build output.
Every byte is pinned by size and SHA256 in `release.json`
(`boards.recomputer-j40.vendor_inputs`) and authenticated by the engineering
manifest like the other bundle files. `nvidia_flash_tools/vendor_inputs.py`
installs them into the fresh private workspace only.

| File | Installed as |
| --- | --- |
| `patches/0001-mb2-bct-skip-carrier-eeprom-read.patch` | applied to `bootloader/tegra234-mb2-bct-common.dtsi` (`cvb_eeprom_read_size <0x100>` to `<0>`); stock SHA256 `42572d28...`, patched `42f96bb9...` |
| `recomputer-j40-qspi.conf` | `Linux_for_Tegra/recomputer-j40-qspi.conf` (the `flash.sh` board name) |
| `dtb/tegra234-j401-p3768-0000+p3767-000{0,1,3,4}-recomputer.dtb` | `kernel/dtb/` |
| `dtbo/tegra234-p3767-camera-p3768-imx219-dual-seeed.dtbo` | `kernel/dtb/` |

The configuration and patch derive from NVIDIA/Seeed BSD-3-Clause files; the
NVIDIA notice in the configuration header applies. Refreshing means copying new
BSP outputs here, updating the pins in `release.json`, and rebuilding the
bundle (new archive and manifest pins).
