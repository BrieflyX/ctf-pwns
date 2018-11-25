# X-nuca 2018 - SSD

Self-implemented device `xnuca` in qemu, using mmio to transfer data.
Unchecked `malloc`, `free` leads us to fastbin attack, modifying `free` got to `system`.

Some information gathering command

```
# On Host
./qemu-system-x86_64 -device help 2>&1 | grep xnuca

# In guest
lspci
cat /proc/iomem
cat /proc/ioports
```