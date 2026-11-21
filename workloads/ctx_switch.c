/* Extra: two threads ping-pong one byte through a pair of pipes, forcing a
 * context switch on every hop -> excessive context switching. */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static int a[2], b[2];

static void *pong(void *arg) {
    (void)arg;
    char c;
    for (;;) { if (read(a[0], &c, 1) != 1) break; if (write(b[1], &c, 1) != 1) break; }
    return NULL;
}

int main(void) {
    if (pipe(a) || pipe(b)) { perror("pipe"); return 1; }
    printf("ctx_switch: pid %d ping-ponging\n", getpid());
    fflush(stdout);
    pthread_t t;
    pthread_create(&t, NULL, pong, NULL);
    char c = 'x';
    for (;;) { if (write(a[1], &c, 1) != 1) break; if (read(b[0], &c, 1) != 1) break; }
    return 0;
}
