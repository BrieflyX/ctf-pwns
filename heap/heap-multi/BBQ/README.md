# BBQ - TWCTF 4th 2018

The vulnerability is an uninitialized variable on the stack, with a buffer controlled on the stack, we can control `eat` target (of course there should be a `0xdeadbeef11`).

The vulner could be exploited in multiple ways, each of them is complicated using heap techniques.