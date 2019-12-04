#!/bin/sh

DIR="$(dirname "$(readlink -f "$0")")"

qemu-system-x86_64 -monitor /dev/null \
    -cpu max,+smap,+smep,check \
    -m 256 \
    -kernel "${DIR}/bzImage" \
    -drive file="${DIR}/disk.img",format=raw -snapshot \
    -append "console=ttyS0 root=/dev/sda  panic=-1" \
    -nographic -no-reboot
