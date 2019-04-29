# *CTF Finals 2019 - Hack Me

A typical kernel pwn with kASLR / SMEP / SMAP. By `ioctl` syscall, we can allocate / write / read chunks `kmalloc`ed. However, the chunk index isn't checked when accessing `pool` array in module. I found some data like symbol information after `pool` array. 