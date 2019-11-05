# \*CTF Finals 2019 - Hack Me

A typical kernel pwn with kASLR / SMEP / SMAP. By `ioctl` syscall, we can allocate / write / read chunks `kmalloc`ed. However, the chunk index isn't checked when accessing `pool` array in module. I find some data like symbol information after `pool` array. Leveraging this data as `size` of chunks makes it easier to craft larget `offset` and `length` in request arguments, hence leads to arbitrary memory read / write.

To leak kernel address, I utilize a pointer to `hackme` module itself to read module code. Due to relocation of addresses in this module, I'm able to leak module address via `add rax, offset pool` instruction. Afterwards, reading relative offset of `call copy_from_user` gives me kernel address. In this challenge's kernel, there is a variable called `current_task` storing current `task_struct` pointer. Thus I leak this pointer and find `cred` structure, then zero out all `0x3e8` and get root shell.
