# LCARS - DEF CON CTF Quals 2019

It is a sandbox-like challenge. The main process `LCARS` forks to execute `.sys` file and `.papp` user app. `LCARS` sets seccomp filters for different permission level and establishes socketpair to communicate with apps. All forked process only keeps fd 0 and 1 to send requests to `LCARS`.

`.sys` would be loaded at address 0 and executed. `init.sys` provides 2 commands `download` and `run`. `download` would write file in its built-in filesystem. `run` would spawn a new process.

When executing `papp` files, it first launches `loader.sys` and checks the headers of `papp` files. We could specify segments in `papp` program header for address, length and prot etc.

Processes have their own permission levels. Low permission process cannot open higher permission files. If we do not sign for `papp` files, the permission level will be set to 3 (lowest). The `loader.sys` sends RPC to `crypto.sys`, checking signature and decrypting code.

## LCARS000

There is a `flag1.papp` which uses `crypto.sys` to encrypt flag. However, to send RPC, it needs to put arguments and buffer into shared memory. After `flag1.papp` exits, I launch my own app and directly read shared memory to leak remaining flag.

Flag is the password of next zip file: `OOO{c1c54538b346dd9c393611af8c06de45}`

## LCARS022

The basic principle is to use `mmap` syscall changing existing memory mapping. When `mmap` a shared memory, it becomes private thus other process wouldn't see changes on this page. I utilize this primitive to forge RPC reponse of `crypto.sys` and keep permission level 1 for my `PAPP` program. Then we could open `flag22.txt` (permission level 1) and print its content.

Flag is the password of next zip file: `OOO{60a80a7021ee5987ad2d47b339d84e4b}`

## LCARS333

It was released quite late and I have no idea about it during competition. It adds a check for `mmap` syscall.

## Author Repo

The author source and exploit repo: https://github.com/o-o-overflow/dc2019q-LCARS000
