# Hitcon 2018 - Abyss

Pwn `user.elf` to open the first flag `flag`. Then pwn the kernel to open arbitrary file, thus get `flag2`. At last, pwn the `hypervisor.elf` to own the host.

## Stage 1 - user.elf

The vulnerability is `swap` operation does not check the stack bounder, thus we can modify the stack pointer to GOT. By adding a value to `printf` got, we can jump to our shellcode.

## Stage 2 - kernel

The kernel handles several syscalls required by libc. But in `read` and `write` handler, it does not check the return value of `kmalloc`. With a null pointer returned, we can overwrite kernel code from address 0, leading to kernel shellcode exectuion.

## Stage 3 - hypervisor.elf

Now we can read arbitrary file on the host, thus having leaks via `/proc/self/maps`.
The hypercall is implemented via the specific I/O port. An unchecked `ioctl` hypercall leads us to control kvm instance. We can set a new phisical memory region for vm, mapping the stack segment into the vm. Then we set a page table entry for the new phisical memory, and search `ioctl(KVM_RUN)` return address on the stack, modifying to our own rop chain.