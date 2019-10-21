# 0CTF 2019 - Baby Heap 2019

The challenge uses libc 2.28 on Ubuntu.

## Vulnerabilities

A null-byte off-by-one when `update` the chunk.

## Exploit

The script [](babyheap2019.py) is the official solution for this challenge. Due to the limitation of chunk size (`0x20`~`0x60`), we need to trigger `malloc_consolidate` to free fastbin chunk. To achieve this purpose, the top chunk should be exhausted.