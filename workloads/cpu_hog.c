/* T1: infinite busy loop -> CPU hog. Usage: cpu_hog [seconds_idle_first] */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1) sleep((unsigned)atoi(argv[1])); /* idle baseline first (lets EWMA learn "normal") */
    printf("cpu_hog: pid %d spinning\n", getpid());
    fflush(stdout);
    volatile unsigned long x = 0;
    for (;;) x++;
}
