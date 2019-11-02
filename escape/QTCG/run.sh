#!/bin/sh

./qemu-system-x86_64 -initrd ./initramfs-busybox-x64.cpio.gz -nographic -kernel ./vmlinuz-5.0.5-generic -append "priority=low console=ttyS0" -monitor /dev/null
