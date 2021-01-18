# Favourite Architecture II - Startctf 2021

A risc-v program running based on qemu user mode with syscall whitelist

```
diff --git a/linux-user/syscall.c b/linux-user/syscall.c
index 27adee9..2d75464 100644
--- a/linux-user/syscall.c
+++ b/linux-user/syscall.c
@@ -13101,8 +13101,31 @@ abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
         print_syscall(cpu_env, num, arg1, arg2, arg3, arg4, arg5, arg6);
     }
 
-    ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
-                      arg5, arg6, arg7, arg8);
+    switch (num) {
+        // syscall whitelist
+        case TARGET_NR_brk:
+        case TARGET_NR_uname:
+        case TARGET_NR_readlinkat:
+        case TARGET_NR_faccessat:
+        case TARGET_NR_openat2:
+        case TARGET_NR_openat:
+        case TARGET_NR_read:
+        case TARGET_NR_readv:
+        case TARGET_NR_write:
+        case TARGET_NR_writev:
+        case TARGET_NR_mmap:
+        case TARGET_NR_munmap:
+        case TARGET_NR_exit:
+        case TARGET_NR_exit_group:
+        case TARGET_NR_mprotect:
+            ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
+                    arg5, arg6, arg7, arg8);
+            break;
+        default:
+            printf("[!] %d bad system call\n", num);
+            ret = -1;
+            break;
+    }
 
     if (unlikely(qemu_loglevel_mask(LOG_STRACE))) {
         print_syscall_ret(cpu_env, num, ret, arg1, arg2,

```


In previous stage (`favourite_architecture 1`), we could gain arbitrary shellcode execution. I started my work from this stage. The goal is to do `execve` syscall.

The main point is as following

- Since we actually run in qemu process, we could read `/proc/self/maps` for leaking qemu memory layout. Although qemu would inspect path we want to open and provide fake data, we can use path like `/./proc/self/maps` to bypass this check.
- In user mode, qemu translate guest address to host address by simply adding `guest_base` offset (in this case it is 0). Lack of sanity check makes us easily overwrite memory of qemu process.
- We choose to overwrite `mprotect` got to `system`, first we need to call original `mprotect` to make it writable. Then we put `/bin/sh` at start of a page and call `mprotect`, which would give us a shell.

## Workdir

- [exp.py](./workdir/exp.py) is the main script, it would compile shellcode and parse leaked mapping file.
- [shellcode1.c](./workdir/shellcode1.c) is the first shellcode, which reads the second shellcode into 0x6c000 and jump onto it.
- [shellcode2.c](./workdir/shellcode2.c) is the second shellcode with main exploit logic.