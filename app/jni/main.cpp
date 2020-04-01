//
// Created by my on 20-4-1.
//
#include "syscall_tracer.h"
#include <stdio.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/wait.h>

int main(int args, char *argv[]) {
    if (args < 2) {
        printf("usage %s <pid_to_attach>\n", argv[0]);
        return -1;
    }
    uid_t uid = getuid();
    if (uid != 0) {
        printf("run in uid %d is not supported, only root is support\n", uid);
        return -2;
    }
    ISysTracer *tracer = sys_tracer_create();

    pid_t trace_pid = atoi(argv[1]);

    signal(SIGCHLD, SIG_IGN);
    int r = ptrace(PTRACE_ATTACH, trace_pid);
    if (r!=0) {
        printf("ptrace attach %d error %s\n", trace_pid, strerror(errno));
        return -3;
    }
    int val = 0;
    printf("waiting pid %d to stop...\n", trace_pid);
    wait(&val); //等待kill stop
    if(WIFEXITED(val)) {
        printf("pid %d has exited...\n", trace_pid);
        return -4;
    }
    printf("tracing, see logcat\n");
    tracer->run(trace_pid);
    printf("trace exit...\n");
    sys_tracer_release(tracer);
    return 0;
}
