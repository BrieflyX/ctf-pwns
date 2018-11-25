# X-nuca 2018 - SSD

Quite similar challenge as defcon quals 2018 [EC3](https://ctftime.org/task/6101)

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
