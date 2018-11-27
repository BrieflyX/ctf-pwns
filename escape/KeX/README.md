# ASIS CTF Finals 2018 - Modern KeX

A mips kernel privilege escalation challenge, no kASLR, no SMEP/SMAP, even no NX and r/w permissions.

The kernel module implements a tiny array management, you could get or set value by index, which is not checked. Thus with a request of a large index, we have aribitrary r/w in kernel. By modifying jumptable using by `kex_ioctl`, we jump to our userland code to commit a root cred. Note to balance the stack and keep original control flow, we modify the return address manully.
