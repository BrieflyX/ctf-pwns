# Hack.lu 2018 - Heap Hell

Similar to Heap Heaven II, but there is no code pointer on the heap. We could leverage the integer underflow, mmap on `0x10000`, then write `0x20001` bytes to make the comparison underflow and passed. After modifying `chain` and `free_hook`, to end the fread process, we could shutdown in one-direction to make it return due to EOF.