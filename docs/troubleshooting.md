# Troubleshooting and recovery

| Symptom | Next action |
| --- | --- |
| No NVIDIA/APX device | Check the board-specific port in the [installation guide](../README.md), direct data cable and power; repeat Force Recovery. Try another data cable. |
| More than one NVIDIA endpoint | Disconnect other devices; retry with only this kit. |
| Unsupported host or missing package | Use physical Ubuntu x86_64; review/run the printed apt command. |
| Archive, image or download hash mismatch | Obtain the exact authenticated build from the operator; do not edit JSON pins. |
| Writable/symlink/foreign-owned path refused | Use a fresh root-owned extraction/session under `/opt`, with non-group/other-writable ancestors. |
| Unsupported module/carrier/fuses or unknown Secure Boot | Stop and confirm labels/security with the operator. Do not invent metadata or enroll keys. |
| USB/SSH/ADB timeout or interrupted write | Preserve the session and STOP message, restore stable power, reenter recovery and review the failure before retrying. Do not reuse a mutated prepared tree. |
| reComputer J40/J4012: `recomputer-j40 carrier refused` or `board changed during carrier EEPROM read` | The carrier EEPROM decoded as an NVIDIA carrier, had an unexpected size, or the board left recovery after the dump. Stop; keep the printed evidence (sha256, decoder output, return code) and see the [carrier rule](reference.md#recomputer-j40). Do not substitute another board selector. |
| Verified write but no boot | Capture serial/UEFI output, confirm image/board and use stock recovery if necessary. |

Logs can contain ECIDs, disk serials and local paths. Share only reviewed/redacted
excerpts, including `first-test-report.json`; nothing is uploaded automatically.

## First-boot diagnostics

On the installed kit, where the image provides these tools:

```sh
uname -a
cat /proc/device-tree/model
cat /proc/cmdline
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS
dmesg | grep -Ei 'nvidia|nvgpu|nvme|error|fail'
```

Confirm release, board device tree and partitions/storage. Run the intended CUDA
workload/smoke test. Record boot, storage and GPU execution separately from write
verification; a successful write does not establish successful boot.

## Stock NVIDIA recovery

Use a fresh official BSP and matching sample rootfs for this exact release/kit,
not the installer's modified session. Stock commands may erase eMMC/NVMe as well
as firmware; back up anything still readable. Review NVIDIA licensing and the
[Quick Start](https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/IN/QuickStart.html).
On Ubuntu:

```sh
tar xf Jetson_Linux_R39.2.1_aarch64.tbz2
sudo tar xpf Tegra_Linux_Sample-Root-Filesystem_R39.2.1_aarch64.tbz2 -C Linux_for_Tegra/rootfs
cd Linux_for_Tegra
sudo ./tools/l4t_flash_prerequisites.sh
sudo ./apply_binaries.sh
```

On Ubuntu 26.04, `l4t_flash_prerequisites.sh` stops because `qemu-user-static`
no longer exists and `tar` needs `bzip2`. Install `bzip2` and NVIDIA's list with
`qemu-user-binfmt` in place of `qemu-user-static` (the installer's host report
prints the exact command). QEMU is only used for `--extra-pkg` installs, which
this installer never requests.

Enter the exact kit's Force Recovery mode. Choose **one** stock command, not an
Admiral image installation:

Thor stock default installation:

```sh
sudo ./l4t_initrd_flash.sh jetson-agx-thor-devkit internal
```

AGX Orin stock internal/eMMC installation:

```sh
sudo ./flash.sh jetson-agx-orin-devkit internal
```

For stock NVMe, follow the respective NVIDIA
[Thor](https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupportJetsonThor.html)
or [Orin](https://docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/FlashingSupport.html)
external-storage guide. Do not translate commands between boards. For a Seeed reComputer J40/J4012 use [Seeed's flashing guide](https://wiki.seeedstudio.com/reComputer_J4012_Flash_Jetpack/) with its own Linux_for_Tegra.
