/* T4: parent that never calls wait() -> exited children stay as zombies (state Z).
 * Usage: zombie [n_children] (default 10) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 10;
    printf("zombie: parent pid %d creating %d zombies\n", getpid(), n);
    fflush(stdout);
    for (int i = 0; i < n; i++)
        if (fork() == 0) _exit(0); /* child exits immediately; parent never reaps it */
    for (;;) pause();              /* parent stays alive, so zombies are never adopted by init */
}
