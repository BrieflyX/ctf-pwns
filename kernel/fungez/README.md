# DEFCON Quals 2020 - fungez

A befunge interpreter implemented in kernel space.

## Vulnerability

The kernel module allocates a program state for each opened fd. When calling `ioctl` to start executing, it puts the task function into a workqueue and starts `fungez_worker` asynchronously.
However, its global structure (stored in in `inode` structure) contains a pointer of `mmap` area, which could be modified during execution by calling start `ioctl` on another fd.

## Exploitation

To exploit this bug, basically we need to open 2 fds, one mmap 0x2000 memory area (fd1) and the other 0x1000 bytes memory area (fd2). Then we call start ioctl on fd1 and fd2, these two `fungez_worker` tasks are added into workqueue. When `fungez_worker` is working on fd1 execution and not finishes yet, the start `ioctl` of fd2 replaces the `mem_ptr` in global structure. Thus when `fungez_worker` continues working on fd1 execution, it actually works on fd2's memory area, which is 0x1000 bytes long. But the limit `mem_size` is still 0x2000, then we could cause out-of-bound read and write over the area.

Since 0x2000 and 0x1000 bytes chunks are `kmalloc`ed, there are `fd` pointer when they are freed. So I choose to leverage this pointer to leak `kmalloc-4k` mem cache address. I searched this slab and found some pci related structure containing pointers to kernel base. Then I corrupted the `fd` pointer to get arbitrary write.

The pitfall is `kmalloc`ed memory is filled with null bytes. When I try to modify `modprobe_path` variable, it also cleans other data around it, which messes the kernel state. To overcome this, I dump the memory when running without kaslr, and dynamically fix all pointers in this page after leaking kernel base. 