mov r14, 0x3731383036323931

mov rdi, 0
mov rsi, 0x200000
mov rdx, 7
mov rcx, 0
mov r8, -1
mov r9, 0
mov rax, 9
syscall
/*push rax
push rax
call print_qword
pop rax*/

mov r15, rax

push r14
call print_qword

xor r13, r13
again:
mov rdi, 0
lea rsi, [r15 + r13]
mov rdx, 1
mov rax, 0
syscall
add r13, rax
cmp r13, 0xD00
jnz again

/*mov rdi, 1
mov rsi, r15
mov rdx, 0xD00
mov rax, 1
syscall*/

mov rdi, 1
mov rsi, r15
mov rdx, 0xFFFFFFFFFFFFFFFF
mov rax, 1
syscall
push rax
call print_qword

push 0x17082619
call print_qword

hlt

print_qword:
push rsi
lea rsi, [rsp + 16]
mov rdx, 8
mov rdi, 1
mov rax, 1
syscall
pop rsi
ret 8
