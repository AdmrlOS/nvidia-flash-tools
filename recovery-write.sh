#!/bin/bash
# Selected Jetson RAM recovery only. Never execute on the Ubuntu host.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
fail() { echo "STOP: $*" >&2; exit 1; }
[ "$#" -ge 2 ] || fail 'usage: recovery-write.sh OP DISK [arguments]'
op=$1 disk=$2; shift 2
[ "$op" = info ] || fail 'destructive recovery path disabled: authenticated installed native exclusive-FD helper integration unqualified; no pathname dd fallback'

[[ "$disk" =~ ^/dev/nvme[0-9]+n[0-9]+$ ]] || fail 'whole NVMe namespace required'
[ "$(id -u)" = 0 ] && [ -b "$disk" ] || fail 'root and NVMe block device required'
[ -f /initrd_flash.cfg ] || fail 'not NVIDIA RAM recovery'
awk '$5 == "/" && / - (rootfs|tmpfs|ramfs) / {ok=1} END {exit !ok}' /proc/self/mountinfo || fail 'root not RAM'
name=${disk##*/}
identity() {
    local entry dev
    [ "$(cat "/sys/class/block/$name/queue/logical_block_size")" = 512 ] || fail '512-byte namespace required'
    [ "$(cat "/sys/class/block/$name/ro")" = 0 ] || fail 'read-only namespace'
    [ ! -e "/sys/class/block/$name/partition" ] || fail 'partition refused'
    for entry in "/sys/class/block/$name" "/sys/class/block/$name"/"${name}"p*; do
        [ -e "$entry/dev" ] || continue
        dev=$(cat "$entry/dev")
        if awk -v dev="$dev" '$3 == dev {found=1} END {exit !found}' /proc/self/mountinfo; then fail 'mounted namespace'; fi
        [ -z "$(ls -A "$entry/holders")" ] || fail 'active holders'
        if grep -Fq "/dev/${entry##*/} " /proc/swaps; then fail 'active swap'; fi
    done
    printf '%s\n' "$(cat "/sys/class/block/$name/device/serial" | xargs)" \
        "$(cat "/sys/class/block/$name/device/model" | xargs)" \
        "$(( $(cat "/sys/class/block/$name/size") * 512 ))" 512 \
        "$(readlink -f "/sys/class/block/$name/device")"
}
identity
