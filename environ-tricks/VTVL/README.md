# Vertical Takeoff Vertical Landing - CodeBlue 2017

Overwrite environment variable on the stack to force `MMAP_THRESHOLD` to 0, then `valloc` initilize the ptmalloc. When allocating chunks, it would use `mmap`.

[Original writeup by binja](http://binja.github.io/2017/11/13/Thoughts-on-CODE-BLUE-CTF-write-ups/#writeup)