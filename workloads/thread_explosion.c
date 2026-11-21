/* T5: program creating hundreds of pthreads. Usage: thread_explosion [n] (default 400) */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *idle(void *arg) { (void)arg; for (;;) pause(); return NULL; }

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 400;
    printf("thread_explosion: pid %d creating %d threads\n", getpid(), n);
    fflush(stdout);
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, 64 * 1024); /* small stacks keep memory use low */
    for (int i = 0; i < n; i++) {
        pthread_t t;
        if (pthread_create(&t, &a, idle, NULL) != 0) { perror("pthread_create"); break; }
        usleep(10000);
    }
    for (;;) pause();
}
