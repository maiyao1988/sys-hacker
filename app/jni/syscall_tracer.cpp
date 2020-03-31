
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include <android/log.h>
#include <fcntl.h>
#include <pthread.h>
#include "syscallents_arm.h"

static bool g_is32bit = true;

void _log(const char *fmt, ...) {
    va_list v;
    va_start(v, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, "sysmnt", fmt, v);
    va_end(v);
}

const char *get_syscall_name(int id) {
    if (id >= MAX_SYSCALL_NUM) {
        _log("get_syscal_name %d out-of-range %d", id, MAX_SYSCALL_NUM);
        //abort();
        return "[unknown]";
    }
    return syscalls[id].name;
}

//#define PTRACE_GETHBPREGS 29
//#define PTRACE_SETHBPREGS 30

int set_syscall_and_wait(pid_t child, int signal=0)
{
    int status;
    int err = 0;

    // Calling ptrace with PTRACE_SYSCALL makes
    // the tracee (child) continue its execution
    // and stop whenever there's a syscall being
    // executed (SIGTRAP is captured).
    err = ptrace(PTRACE_SYSCALL, child, 0, signal);
    if (err == -1) {
        _log("ptrace error");
        return err;
    }

    // Wait until the next signal arrives
    // When the running tracee enters ptrace-stop, it
    // notifies its tracer using waitpid(2)
    // (or one of the other "wait" system calls).
    waitpid(child, &status, 0);

    // Ptrace-stopped tracees are reported as returns
    // with pid greater than 0 and WIFSTOPPED(status) true.
    //
    // -    WIFSTOPPED(status) returns true if the child
    //      process was stopped by delivery of a signal.
    //
    // -    WSTOPSIG(status) returns the number of the signal
    //      which caused the child to stop - should only be
    //      employed if WIFSTOPPED returned true.
    //
    //      by `and`ing with `0x80` we make sure that it was
    //      a stop due to the execution of a syscall (given
    //      that we set the PTRACE_O_TRACESYSGOOD option)
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
        //stop by get syscall
        _log("pid %d stop sig 0x%x", child, WSTOPSIG(status));
        return 0;
    }
    if (WIFSIGNALED(status)) {
        _log("pid %d term by signal %d", child, WTERMSIG(status));
        return 2;
    }

    // Check whether the child exited normally.
    if (WIFEXITED(status)) {
        _log("pid %d exited", child);
        return 1;
    }

    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
        //stop by execve
        _log("stop by execve");
        return set_syscall_and_wait(child);
    }
    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
        _log("stop by clone");
        return set_syscall_and_wait(child);
    }

    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) ||
            status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
        _log("stop by fork/vfork");
        return set_syscall_and_wait(child);
    }

    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        _log("get stop status 0x%x signal %d pass to tracee", status, sig);
        return set_syscall_and_wait(child, sig);
    }

    int n1 = WIFSTOPPED(status);
    int sig = WSTOPSIG(status);
    _log("warning unknown status 0x%x WIFSTOPPED(%d), WSTOPSIG(%d)", status, n1, sig);
    return 3;
}

//TODO:support execve into 64
void *_thread_p(void *p) {
    sleep(1000);
    return 0;
}

void print_call_before(pid_t pid) {
    struct pt_regs regs = {0};
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    int sysid = regs.ARM_r7;
    int p0 = regs.ARM_r0;
    int p1 = regs.ARM_r1;
    int p2 = regs.ARM_r2;
    int p3 = regs.ARM_r3;
    int p4 = regs.ARM_r4;
    int p5 = regs.ARM_r5;
    int p6 = regs.ARM_r6;
    int pc = regs.ARM_pc;
    int lr = regs.ARM_lr;

    const char *name = get_syscall_name(sysid);
    _log("(%d)(%s) (0x%x), [0x%08X] [0x%08X] [0x%08X] [0x%08X] [0x%08X] [0x%08X]", pid, name, sysid, p0, p1, p2, p3, p4, p5, p6);
    _log("(%d)(%s) (0x%x), pc[0x%08X] lr[0x%08X]", pid, name, sysid, pc, lr);
}

void print_call_after(pid_t pid) {
    struct pt_regs regs2;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs2);
    int retval = regs2.ARM_r0;
    int sysid = regs2.ARM_r7;
    const char *name = get_syscall_name(sysid);
    _log("(%d)(%s) (0x%x) return %d\n", pid, name, sysid, retval);
}

void trace1() {
    int val = 0;
    int pid = fork();
    if(pid == 0)
    {
        //signal(SIGINT, SIG_IGN);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        //execl("/system/bin/ls", "ls", NULL);
        pthread_t t;
        _log("before pthread_create");
        pthread_create(&t, 0, _thread_p, 0);
        _log("after pthread_create");

        _log("before write");
        syscall(4, 2, "c111\n", 4);
        _log("after write");
        //exit(1);
        kill(getpid(), SIGINT);
        syscall(1);
        //sleep(3);
    }
    else {

        _log("before wait");
        wait(&val); //等待kill stop
        _log("after wait");

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|
                                          PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_EVENT_VFORK);
        if(WIFEXITED(val)) {
            _log("break1\n");
        }
        //ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        while(1)
        {
            int err = set_syscall_and_wait(pid);
            if (err != 0) {
                break;
            }

            print_call_before(pid);

            err = set_syscall_and_wait(pid);
            if (err != 0) {
                break;
            }

            print_call_after(pid);
        }
        _log("syscall moniter exit");
    }
}

void sys_trace() {
    signal(SIGCHLD, SIG_IGN);
    trace1();
}