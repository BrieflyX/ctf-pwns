# SECCON 2019 Quals - Random Pitfalls

The program `mmap`s 64 continous pages, copies data in 32 of them, and marks others `PROT_NONE`.

The cpu flags show it supports `rtm` instructions, thus we use `xbegin/xend` to access memory in transaction to avoid segmentation fault.