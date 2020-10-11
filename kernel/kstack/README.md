# Kstack - Seccon 2020

A simple stack implemented in kernel, user program could execute `CMD_PUSH` and `CMD_POP`.
It uses a chain list to store all values.

## Vulnerability

The bug is obvious that `push` and `pop` operations are not locked.
On the other hand, when calling `copy_from_user` in push cmd, the value is not initialized, leaving us chance to leak data. (line 30 in `kstack.c`)

## Exploitation

In the challenge we would use `userfaultfd` technique frequently.
At first, to leak kernel base, we choose to put a `shm_file_data` (via creating and attaching a shared memory) structure on the heap (kmalloc-32), then free it. Afterwards, we push a value and use userfault to make main thread hang in `copy_from_user` function. At this time, in fault handling thread, we do a pop operation, the uninitialized value (remaining `struct ipc_namespace *ns` pointer, it will be an address located in kernel data area) is read and we know the kernel base address.

Next, we could trigger double-free using pop cmd. When calling `copy_to_user`, we make main thread hang and in fault handling thread we do a pop cmd again. Thus the same chunk would be freed twice continously, its `fd` ptr points to itself. 

To modify this `fd` to `modprobe_path`, we use `setxattr` syscall to malloc 32 bytes chunk. (See [this post](https://duasynt.com/blog/linux-kernel-heap-spray)). When the syscall doing `copy_from_user`, we make the first 8 bytes copied successfully and remaining 24 bytes located in our registered missing fault page. In that case, at the time we handle this user fault, the first 8 bytes (`fd` pointer) has already been overwritten (with `modprobe_path-8`). Then we push twice and modify `modprobe_path` with value.