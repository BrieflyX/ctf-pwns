# Bufoverflow_B - SCTF 2018

Null-byte off-by-one. Keep chunk number smaller than 2 to avoid data clearing after `malloc` and `free`. Leveraging large bin shoot to overwrite `_IO_list_all`.