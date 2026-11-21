/* T3: CONTROLLED fork bomb. One parent forks children rapidly; each child just
 * sleeps. Hard-capped at 400 children, so it cannot take the machine down.
 * For an uncapped test use a disposable VM with `ulimit -u`.
 * Usage: fork_bomb [max_children] (default 150, max 400) */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int max = argc > 1 ? atoi(argv[1]) : 150;
    if (max > 400) max = 400;
    printf("fork_bomb: parent pid %d spawning %d children\n", getpid(), max);
    fflush(stdout);
    int spawned = 0;
    for (int i = 0; i < max; i++) {
        pid_t c = fork();
        if (c == 0) {
            prctl(PR_SET_PDEATHSIG, SIGTERM); /* children die with the parent */
            sleep(60);
            _exit(0);
        }
        if (c < 0) { perror("fork (process limit reached)"); break; }
        spawned++;
        usleep(20000); /* ~50 forks/s */
    }
    printf("fork_bomb: spawned %d, waiting\n", spawned);
    while (wait(NULL) > 0) {}
    return 0;
}
