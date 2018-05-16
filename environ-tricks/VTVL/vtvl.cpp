/*
    g++ vtvl.cpp -o vtvl -std=c++11 -Wl,-s -Wl,-z,relro,-z,now -fstack-protector-all -fvtable-verify=std -static-libstdc++
 */

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <unistd.h>
#include <errno.h>
using namespace std;

#define myprintf(s) write(1, (s), strlen((s)))
#define myputs(s) write(1, (s "\n"), strlen((s "\n")))

void recvlen(char *buf, size_t n) {
  ssize_t rc;

  while (n--) {
    rc = read(0, buf, 1);
    if (rc == 0) return;
    if (rc == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        continue;
      }
      return;
    }

    if (*buf == '\n') {
      *buf = '\0';
      return;
    }

    buf++;
  }
}

uint64_t GetInt() {
  char buf[0x20] = "";
  recvlen(buf, 0x1f);
  return strtoull(buf, NULL, 10);
}

class Rocket {
public:
  static void *operator new(size_t size, void *buf) { return buf; }
  static void operator delete(void *p, void *buf) {}
  virtual void Operate(uint8_t *op, uint64_t size) {
    uint64_t i;
    int64_t x = 0;
    int64_t y = 100;

    for (i=0; i<size; i++) {
      switch (op[i]) {
      case 'D':
        y--;
        break;
      case 'L':
        x--;
        break;
      case 'R':
        x++;
        break;
      default:
        exit(-1);
      }
    }

    if (x == 0 && y == 0) myputs("The rocket landed successfully.");
    else myputs("Failed.");
  }
};

class UnusedRocket : public Rocket {
  void Operate(uint8_t *op, uint64_t size) {}
};

void ReadLine(char *buf) {
  ssize_t rc;
  while (1) {
    rc = read(0, buf, 1);
    if (rc == 0) break;
    if (rc == -1) {
      if (errno == EAGAIN || errno == EINTR) continue;
      return;
    }

    if (*buf == '\n') {
      *buf = '\0';
      break;
    }
    buf++;
  }
}

char *name;
Rocket *rocket;
char name_dup[64];

void print_banner(void) {
  myputs("                                                                ");
  myputs(" ▄               ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄               ▄  ▄           ");
  myputs("▐░▌             ▐░▌▐░░░░░░░░░░░▌▐░▌             ▐░▌▐░▌          ");
  myputs(" ▐░▌           ▐░▌  ▀▀▀▀█░█▀▀▀▀  ▐░▌           ▐░▌ ▐░▌          ");
  myputs("  ▐░▌         ▐░▌       ▐░▌       ▐░▌         ▐░▌  ▐░▌          ");
  myputs("   ▐░▌       ▐░▌        ▐░▌        ▐░▌       ▐░▌   ▐░▌          ");
  myputs("    ▐░▌     ▐░▌         ▐░▌         ▐░▌     ▐░▌    ▐░▌          ");
  myputs("     ▐░▌   ▐░▌          ▐░▌          ▐░▌   ▐░▌     ▐░▌          ");
  myputs("      ▐░▌ ▐░▌           ▐░▌           ▐░▌ ▐░▌      ▐░▌          ");
  myputs("       ▐░▐░▌            ▐░▌            ▐░▐░▌       ▐░█▄▄▄▄▄▄▄▄▄ ");
  myputs("        ▐░▌             ▐░▌             ▐░▌        ▐░░░░░░░░░░░▌");
  myputs("         ▀               ▀               ▀          ▀▀▀▀▀▀▀▀▀▀▀ ");
  myputs("                                                                ");
}

void service(void) __attribute__((constructor(100)));
void service(void) {
  uint64_t i;
  uint64_t size;
  rocket = new (alloca(sizeof(Rocket))) Rocket;
  name = (char*)alloca(64);

  print_banner();
  myputs("**** Welcome to VTVl(Vertical Takeoff Vertical landing) simulator! ****\n");
  myprintf("Your name: ");
  ReadLine(name);
  memcpy(name_dup, name, 64);
  myprintf("Hi, ");
  myprintf(name);
  myputs("!\n");

  myprintf("Size of operation: ");
  size = GetInt();
  uint8_t *ptr = (uint8_t*)valloc(size+1);
  if (!ptr) {
    myputs("Couldn't allocate the requested size.");
    exit(-1);
  }

  recvlen((char*)ptr, size);
  rocket->Operate(ptr, size);
  myputs("Bye.");
  exit(0);
}

int main(void) {
// We decided to provide no hint or no help in order to adjust the difficulty.
/*  myputs("Hint: see _init_array.");
  myputs("And for simplicity, you may use this if you can.");
  execl("/bin/sh", "/bin/sh", NULL);*/
}