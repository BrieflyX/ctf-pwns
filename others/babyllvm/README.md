# Babyllvm - Codegate CTF 2020

This is a JIT compiler for brainfuck written in python with `llvmlite`.
There are several optimization when generating IR.
The default `whitelist` (0,0) in branch code generation makes it possible to cheat compiler and avoid to generate `ptrBoundCheck`.

Specifically, we can use N `<`s to move stack point out of buffer (when moving there is no check generated), then a followed `[`. In branch code, we first give N `>`s to extend whitelist, thus the memory between `[buf-N, buf]` could be accessed freely.