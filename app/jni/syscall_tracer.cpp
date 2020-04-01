
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
#include <sstream>
#include <sys/prctl.h>
#include "syscallents_arm.h"

struct ProcessStatus {
    short status;
    bool is64bit;
    ProcessStatus()
        : status(0)
        , is64bit(false) {

    }
};

void _log(const char *fmt, ...) {
    va_list v;
    va_start(v, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, "sysmnt", fmt, v);
    va_end(v);
}

#include <map>
class SysTracer {
    //TODO:support execve into 64
    std::map<pid_t, ProcessStatus> mStatus;

    const char *read_string(char *buf, size_t len, pid_t pid, unsigned long addr) {
        if (len % 4) {
            _log("ERROR only 4 align size if support!!!");
            abort();
            return 0;
        }
        unsigned long off = 0;
        unsigned step = sizeof(long);
        while(off < len) {
            long tmp = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0);
            if (tmp < 0) {
                _log("PTRACE_PEEKDATA error");
                buf[off] = 0;
                //abort();
            }

            memcpy(buf+off, &tmp, step);
            off += step;

            char *m = (char*)&tmp;
            bool eos = false;
            for (int i = 0 ; i < step; i++) {
                if (m[i] == 0) {
                    eos = true;
                    break;
                }
            }
            if (eos) {
                break;
            }
        }

        if (off >= len) {
            buf[len - 1] = 0;
        }
        return buf;
    }

    bool get_syscall_entry(syscall_entry &entry, int id) {
        if (id >= MAX_SYSCALL_NUM) {
            _log("get_syscal_entry %d out-of-range %d", id, MAX_SYSCALL_NUM);
            //abort();
            return false;
        }
        entry = syscalls[id];
        return true;
    }

//#define PTRACE_GETHBPREGS 29
//#define PTRACE_SETHBPREGS 30

    void remove_and_clear_id(pid_t &pid) {
        mStatus.erase(pid);
        pid = 0;
    }

    /*
     * params child[in/out] the pid to continue, return the pid return by waitpid(-1)
     * signal
     */
    int continue_syscall_and_wait(pid_t &pid, int signal = 0)
    {
        int status;
        int err = 0;

        // Calling ptrace with PTRACE_SYSCALL makes
        // the tracee (child) continue its execution
        // and stop whenever there's a syscall being
        // executed (SIGTRAP is captured).

        if (pid != 0) {
            err = ptrace(PTRACE_SYSCALL, pid, 0, signal);
            if (err == -1) {
                _log("ptrace error %s", strerror(errno));
                remove_and_clear_id(pid);
                return err;
            }
        }

        // Wait until the next signal arrives
        // When the running tracee enters ptrace-stop, it
        // notifies its tracer using waitpid(2)
        // (or one of the other "wait" system calls).
        pid = waitpid(-1, &status, 0);

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
            _log("pid %d stop sig 0x%x", pid, WSTOPSIG(status));
            return 0;
        }
        if (WIFSIGNALED(status)) {
            _log("pid %d term by signal %d", pid, WTERMSIG(status));
            remove_and_clear_id(pid);
            return 2;
        }

        // Check whether the child exited normally.
        if (WIFEXITED(status)) {
            _log("pid %d exited", pid);
            remove_and_clear_id(pid);
            return 1;
        }

        if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
            //stop by execve
            _log("pid %d stop by execve", pid);
            return continue_syscall_and_wait(pid);
        }
        if (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) ||
            status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) ||
            status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            _log("pid %d stop by fork/vfork/clone", pid);
            pid_t new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) != -1) {
                _log("process %d created\n", new_pid);
                mStatus[new_pid] = ProcessStatus();
                ptrace(PTRACE_SETOPTIONS, new_pid, 0, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|
                                                      PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_EVENT_VFORK);
            }
            return continue_syscall_and_wait(pid);
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            _log("get stop status 0x%x signal %d pass to tracee", status, sig);
            return continue_syscall_and_wait(pid, sig);
        }

        int n1 = WIFSTOPPED(status);
        int sig = WSTOPSIG(status);
        _log("warning unknown status 0x%x WIFSTOPPED(%d), WSTOPSIG(%d)", status, n1, sig);
        remove_and_clear_id(pid);
        return 3;
    }


    void on_before_syscall(pid_t pid) {
        struct pt_regs regs = {0};
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        int sysid = regs.ARM_r7;
        int pc = regs.ARM_pc;
        int lr = regs.ARM_lr;
        syscall_entry e = {0};
        bool r = get_syscall_entry(e, sysid);
        if (!r)
            return;

        const char *name = e.name;
        std::stringstream ss;
        char tmpbuf[32] = {0};
        for (int i = 0; i < e.nargs; i++) {
            int type = e.args[i];
            if (type == ARG_STR) {
                read_string(tmpbuf, sizeof(tmpbuf), pid, (unsigned long)regs.uregs[i]);
                ss<<","<<tmpbuf;
            }
            else if (type == ARG_INT) {
                ss<<","<<regs.uregs[i];
            }
            else if (type == ARG_PTR) {
                char tmp[16] = {0};
                sprintf(tmp, ",0x%08X", (unsigned)regs.uregs[i]);
                ss << tmp;
            }
            else{
                _log("ERROR unknown param type %d", type);
                abort();
            }

        }

        std::string s = ss.str();
        const char *cs = s.c_str();
        if (cs[0] != 0) {
            cs += 1;
        }
        _log("[%d](0x%x) %s(%s) pc[0x%08X] lr[0x%08X]", pid, sysid, name, cs, pc, lr);
    }

    void on_after_syscall(pid_t pid) {
        struct pt_regs regs2;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs2);
        int retval = regs2.ARM_r0;
        int sysid = regs2.ARM_r7;
        syscall_entry e = {0};
        bool r = get_syscall_entry(e, sysid);
        if (!r)
            return;

        const char *name = e.name;
        _log("[%d](0x%x) (%s) return %d\n", pid, sysid, name, retval);
    }

    ProcessStatus &safe_get(pid_t pid) {
        std::map<pid_t, ProcessStatus>::iterator it = mStatus.find(pid);
        if (it != mStatus.end()) {
            return it->second;
        }
        else {
            _log("ERROR pid %d not find in maps", pid);
            abort();
        }
        _log("ERROR pid %d impossible here", pid);
        abort();
    }

public:
    SysTracer() {

    }
    ~SysTracer() {

    }

    void run(pid_t pid) {

        _log("11");
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|
                                          PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_EVENT_VFORK);
        _log("22");
        mStatus[pid] = ProcessStatus();
        _log("33");
        while(1)
        {
            int err = continue_syscall_and_wait(pid);
            if (err != 0) {
                if (mStatus.empty()) {
                    break;
                }
                continue;
            }

            ProcessStatus &st = safe_get(pid);
            if (st.status == 0) {
                st.status = 1;
                on_before_syscall(pid);
            }
            else if (st.status == 1){
                st.status = 0;
                on_after_syscall(pid);
            }
            else {
                _log("ERROR impossible status %d", st.status);
                abort();
            }
        }
        _log("syscall moniter exit");
    }

};

void *_thread_p(void *p) {
    //sleep(1000);
    return 0;
}

void sys_trace2() {
    prctl(PR_SET_DUMPABLE, 1);
    int pid = fork();
    if(pid == 0) {
        //child
        pid_t ppid = getppid();
        signal(SIGCHLD, SIG_IGN);
        int r = ptrace(PTRACE_ATTACH, ppid);
        if (r!=0) {
            _log("ptrace attach %d error %s", ppid, strerror(errno));
            return;
        }
        int val = 0;
        _log("before wait");
        wait(&val); //等待kill stop
        _log("after wait");
        if(WIFEXITED(val)) {
            _log("break1\n");
        }
        char bb[50] = {0};
        sprintf(bb, "%d", ppid);
        execl("/system/bin/strace", "strace", "-p", bb, NULL);
        /*
        SysTracer tracer;
        tracer.run(ppid);
         */

    }
    else {
        //parent
        _log("before go...");
        syscall(4, 2, "parent write\n", 12);
        _log("go...");
    }
}

void sys_trace() {
    //sys_trace2();
    //return;
    int v = 0;
    int pid = fork();
    if(pid == 0)
    {
        //signal(SIGINT, SIG_IGN);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        //execl("/system/bin/ls", "ls", NULL);
        pthread_t t;
        _log("before pthread_create");
        //pthread_create(&t, 0, _thread_p, 0);
        /*
        pid_t n = fork();
        if (n==0) {
            sleep(1);
            syscall(1);
            return;
        }
         */
        _log("after pthread_create");

        _log("before write");
        syscall(4, 2, "c111dstt买\n", 4);
        _log("after write");
        //exit(1);
        kill(getpid(), SIGINT);
        syscall(1);
        //sleep(3);
    }
    else {
        signal(SIGCHLD, SIG_IGN);
        int val = 0;
        _log("before wait");
        wait(&val); //等待kill stop
        _log("after wait");
        if(WIFEXITED(val)) {
            _log("break1\n");
        }

        SysTracer tracer;
        tracer.run(pid);

    }
}

