# CG_CASINO - Codegate 2019 Preliminary

A leak of stack address makes it possible to put fake environ variables on the stack. Thus controlling `/proc/self/environ` leads to arbitrary file upload. Then use `LD_PRELOAD` to inject shellcode when executing `/usr/bin/clear`.
