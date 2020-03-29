#include "Substrate/SubstrateHook.h"

#include <jni.h>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <unistd.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/mman.h>
#include "StackDump.h"
#include "ElfUtils.h"
#include "../../../../Android/Sdk/android-ndk-r14b/platforms/android-21/arch-arm64/usr/include/signal.h"

#define TAG "REV-DEMO"

typedef ssize_t (*fnread) (int fd, void *buf, size_t count);
fnread ori_read = read;

ssize_t my_read(int fd, void *buf, size_t count) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "read call fd=%d, buf=%p, count=%u", fd, buf, count);
    DUMP_CALL_STACK(TAG);
    return ori_read(fd, buf, count);
}
extern "C" JNIEXPORT int test(int argc, const char **argv) {
    int s = atoi(argv[1]);
    int a = 0;
    if (a>5) {
        a = a+1;
        printf("a %d", a);
    }
    else {
        a *= 2;
        printf("a %d", a);
    }
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_reverse_my_reverseutils_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

    __android_log_print(ANDROID_LOG_INFO, TAG, "before hook %p", ori_read);
    MSHookFunction((void*)read, (void*)my_read, (void**)&ori_read);
    __android_log_print(ANDROID_LOG_INFO, TAG, "after hook %p", ori_read);

    //inline_hook_check("libc.so");
    inline_hook_check("libart.so");

    std::vector<int> v;
    v.push_back(3);
    v.push_back(5);
    std::vector<int>::iterator it = v.begin();
    for (;it != v.end(); it++) {
        printf("%d", *it);
    }

    std::string s = "abc";
    s = s + "ccc";
    printf("string %s", s.c_str());

    if (s == "bbb") {
        printf("hello world %d", s.find("kkk"));
    }

    /*
    void *p = fake_dlopen("libc.so", 0);
    fnread f = (fnread ) fake_dlsym(p, "read");
    fake_dlclose(p);
     */

    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

int get_tracer() {
    char line[255] = {0};
    const char *name = "/proc/self/status";
    FILE *f = fopen(name, "r");

    int iid = 0;
    while(!feof(f)) {
        fgets(line, sizeof(line), f);
        if (strstr(line, "TracerPid")) {
            const char *sp = strchr(line, ':');
            const char *id = sp + 1;
            iid = atoi(id);
            break;
        }
    }
    fclose(f);
    return iid;

}

void wait_for_attach() {
    while (1){
        int id = get_tracer();
        if (id != 0) {
            __android_log_print(ANDROID_LOG_INFO, "librev-dj", "debugger attached trace_id:%d...", id);
            break;
        }
        __android_log_print(ANDROID_LOG_INFO, "librev-dj", "waiting attach...");
        sleep(1);
    }

}

typedef int (*sys_type)(int num, int p1, int p2, int p3);
sys_type sys_ori = 0;

int __sys_c(int num, int p1, int p2, int p3) {
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "num %d is call", num);
    return sys_ori(num, p1, p2, p3);
}

typedef int (*pthread_create_type)(pthread_t *thread, pthread_attr_t const * attr,
                   void *(*start_routine)(void *), void * arg);

pthread_create_type pthread_create_ori = 0;
int my_pthread_create(pthread_t *thread, pthread_attr_t const * attr,
                                   void *(*start_routine)(void *), void * arg) {
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "call pthread_create");
    int r = pthread_create_ori(thread, attr, start_routine, arg);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after call pthread_create %d, route %p",
                        (int)(*thread), start_routine);
    return r;
}


typedef int (*cb_type) (void *p);
cb_type cb = 0;
cb_type cb2 = 0;

int my_cb (void *p) {
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cb call skip!!!");
    return 0;
    return cb(p);
}

int my_cb2 (void *p) {
    //DUMP_CALL_STACK("lib-rev-dj");
    sleep(100000);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cb2 call skip!!!");
    return 0;
    //return cb2(p);
}
struct sigaction old_action;

void my_sigaction(int signal, siginfo_t *info, void *reserved) {
    // Here catch the native crash
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "get signal %d %d", signal, info->si_code);
    ucontext_t *c = (ucontext_t*)reserved;
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "pc=%p lr=%p", (void*)c->uc_mcontext.arm_pc, (void*)c->uc_mcontext.arm_lr);
    old_action.sa_sigaction(signal, info, reserved);
}

int loadSigaction() {
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "set signal handler");
    struct sigaction handler = {0};
    handler.sa_sigaction = my_sigaction;
    // 信号处理之后重新设置为默认的处理方式。
    //    SA_RESTART：使被信号打断的syscall重新发起。
    //    SA_NOCLDSTOP：使父进程在它的子进程暂停或继续运行时不会收到 SIGCHLD 信号。
    //    SA_NOCLDWAIT：使父进程在它的子进程退出时不会收到SIGCHLD信号，这时子进程如果退出也不会成为僵 尸进程。
    //    SA_NODEFER：使对信号的屏蔽无效，即在信号处理函数执行期间仍能发出这个信号。
    //    SA_RESETHAND：信号处理之后重新设置为默认的处理方式。
    //      SA_SIGINFO：使用sa_sigaction成员而不是sa_handler作为信号处理函数。
    handler.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV,  // 代表信号编码，可以是除SIGKILL及SIGSTOP外的任何一个特定有效的信号，如果为这两个信号定义自己的处理函数，将导致信号安装错误。
              &handler, // 指向结构体sigaction的一个实例的指针，该实例指定了对特定信号的处理，如果设置为空，进程会执行默认处理。
              &old_action); // 和参数act类似，只不过保存的是原来对相应信号的处理，也可设置为NULL。

    return 0;
}


__attribute__((constructor)) void __init__() {
    //__android_log_print(ANDROID_LOG_INFO, "librev-dj", "librev call!!!");
    const char *path = "/proc/self/cmdline";
    char buf[300] = {0};
    FILE *f = fopen(path, "rb");
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    const char *pkgName = "com.ss.android.ugc.aweme";
    //__android_log_print(ANDROID_LOG_INFO, "librev-dj", "pkg_name %s", buf);
    //__android_log_print(ANDROID_LOG_FATAL, TAG, "cmdline %s", buf);
    if (strcmp(buf, pkgName)!=0) {
        //__android_log_print(ANDROID_LOG_FATAL, TAG, "%s not the target pkgName", pkgName);
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "douyin call!!!");
    char cms_path[255];
    sprintf(cms_path, "/data/data/%s/lib/libcms.so", pkgName);
    void *cms = dlopen(cms_path, RTLD_NOW);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cms %p", cms);
    loadSigaction();

    MapInfo mapInfo;
    get_map_infos(&mapInfo, "libcms.so");

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cms base %p", mapInfo.baseAddr);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cms end %p", mapInfo.endAddr);

    void *hook_anti_cb = (void*)((unsigned)mapInfo.baseAddr + 0x0005C070+1);

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook");
    MSHookFunction((void*)hook_anti_cb, (void*)my_cb, (void**)&cb);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook %p", cb);


    void *hook_anti_cb2 = (void*)((unsigned)mapInfo.baseAddr + 0x00065ED0+1);
    //0x66116 read syscall addr

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook2");
    MSHookFunction((void*)hook_anti_cb2, (void*)my_cb2, (void**)&cb2);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook 2 %p", cb2);

    void *syscall = (void*)((unsigned)mapInfo.baseAddr + 0x00009E7C);


    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook");
    MSHookFunction((void*)syscall, (void*)__sys_c, (void**)&sys_ori);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook %p", sys_ori);

    /*
    void *b = (void *)((unsigned )syscall & (~0x0FFF));
    mprotect(b, 0x1000, PROT_NONE);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "mprotect %p", b);
     */

    /*
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook pthread");
    MSHookFunction((void*)pthread_create, (void*)my_pthread_create, (void**)&pthread_create_ori);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook pthread %p", pthread_create_ori);
     */

    __android_log_print(ANDROID_LOG_FATAL, "librev-dj", "pkgName %s here", buf);
    //wait_for_attach();
}
