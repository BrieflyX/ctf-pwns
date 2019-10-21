/* vim:set ai sw=4 ts=4 et: */
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <syscall.h>
#include <seccomp.h>
#include <fcntl.h>

#define NPAGES      64
#define NSAMPLES    32
#define FLAGSIZE    40

#define internal_error() {fprintf(stderr, "Internal error at line %d\n", __LINE__);exit(-1);}

int goto_jail(void *buf, size_t size)
{
    scmp_filter_ctx ctx;
    if((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL){
        return -1;
    }
    if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 3,
    SCMP_A0(SCMP_CMP_EQ, 1), SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)buf),
    SCMP_A2(SCMP_CMP_EQ, size)) < 0){
        return -1;
    }
    if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0){
        return -1;
    }
    if(seccomp_load(ctx) < 0){
        return -1;
    }
    seccomp_release(ctx);
    return 0;
}

int readfile(char *fname, char *buf, size_t size)
{
    int     fd;
    ssize_t rslt;
    size_t  size_to_read = size;
    if((fd = open(fname, O_RDONLY)) < 0){
        return -1;
    }
    while(size_to_read > 0){
        if((rslt = read(fd, &buf[size - size_to_read], size_to_read)) <= 0){
            break;
        }
        size_to_read -= rslt;
    }
    close(fd);
    if(rslt < 0){
        return -1;
    }
    return size - size_to_read;
}

void xorbuf(char *dst, char *src, size_t size)
{
    while(size-- > 0){
        *dst++ ^= *src++;
    }
}

int main(int argc, char *argv[])
{
    FILE        *fp;
    uint8_t     *mempages, *target_page, buf[FLAGSIZE];
    char        *line = NULL, *eol;
    ssize_t     readsz;
    size_t      len = 0;
    uint32_t    rndval, eax, ebx, ecx, edx;
    uint64_t    selected_pages = 0;
    int         cnt, cursor, page_offset, pgsize = getpagesize();
    __attribute__((noreturn)) void*(*shellcode)(void*, void*);

    // write banner
    if((fp = fopen("/proc/cpuinfo", "r")) == NULL){
        internal_error();
    }
    while((readsz = getline(&line, &len, fp)) != -1){
        if(!strncmp(line, "flags", 5)){
            if(eol = strchr(line, '\n')){
                *eol = '\0';
            }
            puts(line);
            fflush(stdout);
            break;
        }
    }
    if(line) free(line);
    fclose(fp);

    // allocate memory pages
    if((mempages = mmap(NULL, pgsize * NPAGES, PROT_NONE,
    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED){
        internal_error();
    }

    // store flag materials on randomly selected pages
    memset(buf, 0x00, sizeof(buf));
    for(cnt = 0; cnt < NSAMPLES; cnt++){
        if(syscall(SYS_getrandom, &rndval, sizeof(rndval), 0) < 0){
            internal_error();
        }
        rndval %= NPAGES - cnt;
        for(page_offset = 0, cursor = 0; page_offset < NPAGES; page_offset++){
            if(selected_pages & (1ULL << page_offset)){
                continue;
            }
            if(cursor++ == rndval){
                selected_pages |= (1ULL << page_offset);
                target_page = mempages + page_offset * pgsize;
                mprotect(target_page, pgsize, PROT_READ | PROT_WRITE);
                if(cnt == NSAMPLES - 1){
                    // store xored flag
                    if(readfile("FLAG", target_page, FLAGSIZE) < 0){
                        internal_error();
                    }
                    xorbuf(target_page, buf, FLAGSIZE);
                }else{
                    // store random bytes
                    if(syscall(SYS_getrandom, target_page, sizeof(buf), 0) < 0){
                        internal_error();
                    }
                    xorbuf(buf, target_page, FLAGSIZE);
                }
                break;
            }
        }
    }

    // receive shellcode
    if((shellcode = mmap(NULL, pgsize, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED){
        internal_error();
    }
    char prologue[] = "\x31\xC0\x31\xC9\x31\xD2\x31\xDB\x31\xE4\x31\xED\x4D\x31\xC0\x4D\x31\xC9\x4D\x31\xD2\x4D\x31\xDB\x4D\x31\xE4\x4D\x31\xED\x4D\x31\xF6\x4D\x31\xFF";
    memcpy(shellcode, prologue, sizeof(prologue)-1);
    fread(shellcode + sizeof(prologue)-1, 1, pgsize - sizeof(prologue), stdin);
    if(mprotect(shellcode, pgsize, PROT_READ|PROT_EXEC) < 0){
        internal_error();
    }

    // call seccomp
    if(goto_jail(buf, sizeof(buf)) < 0){
        internal_error();
    }

    // clear local variables
    target_page = NULL; memset(buf, 0x00, sizeof(buf));
    cnt = cursor = page_offset = pgsize = rndval = selected_pages = 0;

    // execute shellcode
    shellcode(mempages, buf);

    return 0;
}
