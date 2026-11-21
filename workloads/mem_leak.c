/* T2: malloc() in a loop without free() -> steadily rising RSS.
 * Usage: mem_leak [MB_per_second] [cap_MB]   (defaults 8 MB/s, cap 1024 MB) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int rate = argc > 1 ? atoi(argv[1]) : 8;
    int cap = argc > 2 ? atoi(argv[2]) : 1024;
    printf("mem_leak: pid %d leaking %d MB/s up to %d MB\n", getpid(), rate, cap);
    fflush(stdout);
    for (int total = 0;; ) {
        if (total < cap) {
            for (int i = 0; i < 4; i++) {  /* 4 chunks per second for a smooth slope */
                size_t sz = (size_t)rate * 1024 * 1024 / 4;
                char *p = malloc(sz);
                if (p) memset(p, 1, sz); /* touch pages so they become resident (RSS) */
                usleep(250000);
            }
            total += rate;
        } else sleep(1);  /* leaked memory is never freed */
    }
}
