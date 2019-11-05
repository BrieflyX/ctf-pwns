# P4 Teaser CONFidence CTF - p4fmt

A custom binary format starts with `P4` bytes.

## Leak

When reading program header, the `phoff` is not checked properly. Thus we could leak pointers near our file buffer, e.g., `cred` pointer in `linux_binprm` structure.

## Null-byte write

When a segment is not loaded by file (`addr & 8 == 1`), `_clear_user` would be called to zero-fill user pages. However, it could write null bytes at arbitrary address including kernel space.

## Exploit

In general, I create 2 binaries. One for leaking `cred` pointer, and the other is generated dynamiclly to overwrite the `uid` in `cred` structure. When `install_exec_creds` is called, the process would be root, then it uses shellcode to spawn a root shell.