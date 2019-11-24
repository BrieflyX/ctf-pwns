# Knote V2 - D^3 CTF 2019

## Vulnerability

The `edit` and `get` functions are implemented without lock, thus could be affected by another thread calling `del`.
If we could `del` the chunk between checking and copying process of `edit` / `get`, an UAF will occur.

## Exploit

Since we could only `ioctl` 9 times during one device open, we need some more deterministic techniques to exploit this race bug. I choose to use `userfaultfd` that can hang up copying process in `edit` and `get`, then `del` the corresponding chunk, open `/dev/ptmx` to occupy this space. When copying thread is waked, it will access data which  actually belongs to `tty_struct`.

Due to SMEP/SMAP enabled, we need to pivot stack when controlling eip. The typical `xchg rax, rsp / mov rsp, rax` do not work since `rax` points to code address. However, I find when calling `ioctl` on `/dev/ptmx`, `rbp` points to `tty_struct` we overwrite, thus a `leave; ret` would help us to pivot stack onto `tty_struct`.

The whole exploit is [here](./release.c)