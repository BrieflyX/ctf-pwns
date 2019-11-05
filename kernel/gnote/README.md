# Gnote - TWCTF 2019

Linux kernel pwn, with source code.

## Vulnerability

It is obvious that the memory is not initialized after allocation, which offers information disclosure.

However, source code provided does not show the other bug because it is produced during compiling time.

When checking `switch` statement index, it fetches index from userspace for 2 times, dereferring pointer directly instead of using `copy_from_user`. That gives us a one-instruction window to race for large jumptable index, thus gives us ability to hijack control flow.

## External writeups

[https://rpis.ec/blog/tokyowesterns-2019-gnote/](https://rpis.ec/blog/tokyowesterns-2019-gnote/)
[https://github.com/zzoru/ctf/blob/master/write-ups/2019/twctf/gnote/ex.c](https://github.com/zzoru/ctf/blob/master/write-ups/2019/twctf/gnote/ex.c)
