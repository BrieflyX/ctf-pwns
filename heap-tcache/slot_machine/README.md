# Hack.lu 2018 - Slot Machine

Only 8 times write / free / malloc, only write 8 bytes at pointer address.

Leverage structure of tcache

```
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

increase count to be a fake size (0x100), then free it, modifying its fd to change first element `entries`, which is corresponding to 0x20 chunk.