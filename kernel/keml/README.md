# DEFCON Quals 2020 - keml

Kernel emulator

I didn't work on this challenge during competition.

Basically, we could drain `kmalloc` slab and force it to call `get_free_page` for more memory space. Thus we get the chance to put `kmalloc`ed objects behind controlled pages (since they are all allocated by buddy system). Then out-of-bound write/read is able to modify pointer in these structures.

Official repo: https://github.com/o-o-overflow/dc2020q-keml-public