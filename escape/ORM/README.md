# ORMAPP,ORM - Codegate CTF 2020

The customized CPU emulator and loader.
The challenge consists of two parts, exploiting `chal.ormb` (user application) and exploiting `orm` (emulator).
I only solved `ORM-APP` during the competition.

## ORM VM

This is a stack-based VM which is composed of 2 stacks (I denote them `L` and `R`), 1 register (I denote it `V`) and memory. The instruction is only one byte encoded.
Bit 3~7 represents opcode. Bit 2 represents op1 stack type. Bit 0-1 represents op2 type (0: immediate number, 1: `L` stack, 2: `R` stack, 3: `V`)

Therefore, 5 bits encode 32 types of instructions. I writed a disassembler [objdump.py](./objdump.py) to dump the assembly code for `chal.ormb`. Check [asm.S](./asm.S) for code. Note that it uses stack `R` to store control flow related value (e.g., return address) and stack `L` to store data flow related value (e.g., function parameter), thus increases difficulty of exploiting.

## chal.orb

Common menu-based challenge, containing 6 segments.
```
[+] Wordlen: 8, Entry: 0x8080808080808000, Stacksize: 0x4000, Segnum: 6
[+] Segment addr: 0x1f10000, length: 0x1000, filelen: 0x1000, flag: 3
[+] Segment addr: 0x9000000000, length: 0x1000, filelen: 0x30, flag: 3
[+] Segment addr: 0x8000000000, length: 0x1000, filelen: 0x43f, flag: 4
[+] Segment addr: 0x9090909090909000, length: 0x1000, filelen: 0x1e0, flag: 1
[+] Segment addr: 0xa0a0a0a0a0a0a000, length: 0x2000, filelen: 0x14c8, flag: 3
[+] Segment addr: 0x8080808080808000, length: 0x1000, filelen: 0x66a, flag: 4
```

`0x8000000000` and `0x8080808080808000` are 2 executable segments, which are library code and main logic accordingly.

The app contains 3 functions `[A]dd project`, `[S]how project` and `[M]igrate project`.

When adding project, the code is like

```
808080808080805B:	push R V
808080808080805C:	push R 0xA0A0A0A0A0A0B000
8080808080808065:	ldq R
8080808080808066:	push L V
8080808080808067:	pop L
8080808080808068:	push L V
8080808080808069:	push R 0x1
8080808080808072:	add R V
8080808080808073:	push L V
8080808080808074:	stq L 0xA0A0A0A0A0A0B000
808080808080807D:	pop L
808080808080807E:	push L V
808080808080807F:	push L V
8080808080808080:	push L V
8080808080808081:	push R 0xA0A0A0A0A0A0B008
808080808080808A:	push R 0x8
8080808080808093:	mul L R
8080808080808094:	add R V
8080808080808095:	push R V
8080808080808096:	push R 0xA0A0A0A0A0A0B048
808080808080809F:	push R 0x90
80808080808080A8:	mul L R
80808080808080A9:	add R V
80808080808080AA:	push L V
80808080808080AB:	pop R
80808080808080AC:	stq L V
```

Thus we could infer that, `0xA0A0A0A0A0A0B000` is the number of projects, `0xA0A0A0A0A0A0B008`~`0xA0A0A0A0A0A0B048` is the array of project pointer. Starting from `0xA0A0A0A0A0A0B048`, there is project data, `0x90` bytes for each.

Since there is no limitation on number of projects, when we add more than 8 projects, the pointer array would overflow into project data.

## Exploit

Note that in read-only segment (`0x9090909090909000`), there is a string `====== CENSORED: FLAG LOCATED HERE. ======`. To exploit ORM-APP, we need to leak this string.

Trying several times, I found that after adding 8 projects then a migrate would trigger segmentation fault. Debugging shows we can corrupt stack `R` which return addresses are stored, and there cannot be null-byte.

I didn't figure out what exact reason triggers vulnerability. It seems that migrate function calls `strcpy` to copy project name onto stack `R`. Because in normal it reads 7 bytes into 8-bytes buffer, there is a null-byte preventing overflow. However, I guess, when adding more than 8 projects, the name buffer would be overwritten by a buffer pointer (which is `0xA0A0A0A0...` with no null-byte). Thus `strcpy` would also copy `description` content onto stack and cause corruption of stack `R`.

I chose to return to `80808080808084B6` which prints `[+] Migrating ` string (the original call only writes 14 bytes). As long as there is a huge value resides on stack `L`, we could leak many bytes including flag string.

```
80808080808084AD:	push L 0xE
80808080808084B6:	push L 0x90909090909091A8	; '[+] Migrating ====== CENSORED: F'
80808080808084BF:	push L 0x1
80808080808084C8:	call write
```

Here is full [exploit](./exp_orm_app.py).