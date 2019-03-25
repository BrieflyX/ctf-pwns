# 0CTF 2019 - babyaegis

A menu-style challenge protected under ASAN, UBSAN, LSAN and CFI(?)

## Vulnerabilities

- After deleting notes, the pointer will not be cleaned, which causes an UAF.
- When updating notes, the `read_until_nl_or_max` function returns the wrong length if the input does not end with `\n`, which causes an overflow on asan heap.
- An arbitrary null-byte write on asan shadow memory.

## Exploit

We need to modify the metadata between 2 chunks (redzone) to make asan recycle the freed chunk. We modify the chunk size over 256MB and free it. Then asan would reuse the previous freed chunk, letting us control the content pointer.