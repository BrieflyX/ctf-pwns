// gcc -nostdlib -fpie -e main test.c -o test && objcopy -O binary --only-section=.text test test.bin
#define DATA 0x20000000
#define SPAGE 0x30000000
#define APP_MEM(x) (0x40000000 + ((x) << 24))
typedef unsigned long long int size_t;

struct Request {
	int req;
	int arg0;
	int arg1;
	int arg2;
	int arg3;
};

struct iovec { 
	void  *iov_base;
	size_t iov_len;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	size_t msg_iovlen;
	void *msg_control;
	size_t msg_controllen;
	int msg_flags;
};

int main() {
	char str[] = "I'm superman\n";
	char filename[] = "flag22.txt";
	int fd = openfile(filename);

	int offset = malloc(0x80);
	read(fd, SPAGE+offset, 0x80);
	request(0, offset, 0x80, 0, 0);
	show_message(str, strlen(str));
	exit(0xEF);
}

int request(int req, int arg0, int arg1, int arg2, int arg3) {
	struct Request r;
	r.req = req;
	r.arg0 = arg0;
	r.arg1 = arg1;
	r.arg2 = arg2;
	r.arg3 = arg3;

	write(0, &r, 20);
	int res;
	read(1, &res, 4);
	return res;
}

int strlen(char *str) {
	int i;
	for (i = 0; str[i] != '\0'; i++);
	return i;
}

// Request 0
int show_message(char *msg, int len) {
	int offset = malloc(len);
	char *shared = SPAGE + offset;
	memcpy(shared, msg, len+1);
	return request(0, offset, len, 0, 0);
}

// Request 5
int openfile(char *filename) {
	int len = strlen(filename) + 1;
	int offset = malloc(len);
	memcpy(SPAGE+offset, filename, len);
	int result = request(5, offset, len, 0, 0);
	if (!result) {
		struct msghdr msg;
		struct iovec iov;
		char iovbuf[1];
		char msgbuf[0x100];
		iov.iov_base = iovbuf;
		iov.iov_len = 1;
		msg.msg_flags = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = msgbuf;
		msg.msg_controllen = 0x100;
		if ( recvmsg(1, &msg, 0x100) < 0 ) exit(0xEE);
		if (msg.msg_controllen > 0xF) {
			return *(int *)(msg.msg_control+16);
		}
		return -1;
	} else return -1;
}

void memcpy(char *dst, char *src, int sz) {
	for (int i = 0; i < sz; i++) {
		dst[i] = src[i];
	}
	return;
}

int malloc(int a1) {
  long result; // rax
  unsigned int v2; // edi
  unsigned char v3; // cf
  unsigned char v4; // zf
  unsigned int *heap = 0x20000004;

  result = 0xFFFFFFFF;
  if ( a1 <= 0x1000000 )
  {
    result = heap[0];
    v2 = (a1 + 15) & 0xFFFFFFF0;
    v3 = v2 + heap[0] < 0xFFFFFF;
    v4 = v2 + heap[0] == 0xFFFFFF;
    if ( v2 + heap[0] <= 0xFFFFFF )
      v2 += heap[0];
    if ( !(v3 | v4) )
      result = 0;
    heap[0] = v2 & 0xFFFFFF;
  }
  return result;
}

int read(int fd, char *buf, long sz) {
	asm("movl $0, %eax\n" \
		"syscall\n");
}

int write(int fd, char *buf, long sz) {
	asm("movl $1, %eax\n" \
		"syscall\n");
}

void exit(int no) {
	asm("movl $0x3C, %eax\n" \
		"syscall\n");
}

int recvmsg(int fd, void * msg, unsigned int flags) {
	asm("movl $0x2F, %eax\n" \
		"syscall\n");
}