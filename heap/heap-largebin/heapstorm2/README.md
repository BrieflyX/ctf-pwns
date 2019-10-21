# Heap Storm II - 0ctf quals 2018

Corrupt large bin chunk's `bk_nextsize`, trigger code that put unsorted bin chunk into large bin list. Crafting their size relationship to achieve arbitrary shoot. Putting a `size` and `bk` pointer on the uncontrolled area, then unsorted bin attack wouldn't crash the program when there is a valid `bk` pointer.