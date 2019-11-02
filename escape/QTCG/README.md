# QTCG - XCTF Finals 2019

This challenge implements a hypercall with `vmmcall` instruction in QEMU TCG. Main logic is in `helper_vmmcall2`.
To call this function, we need to execute `vmmcall` in kernel space and pass argument via `rax`, `rdi`, `rsi` and `rdx`.
The vulnerability is trival that there is arbitrary heap overflow, we can modify `free` pointer to `system`.

My exploit is a kernel module `pwn.c`. To build `.ko`, we need `linux-5.0.5` source code with `make modules_prepare` executed. The exploit will launch when executing `insmod`, it is quite unstable.