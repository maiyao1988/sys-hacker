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
    //原函数是靠r0-r7传递参数的，所以只hook前四个参数，后面不符合函数调用约定了
    int trueNum = num - 0xE9;
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "num 0x%x is call [0x%08X] [0x%08X] [0x%08X]", trueNum, p1, p2, p3);
    return sys_ori(num, p1, p2, p3);
}
sys_type sys_ori2 = 0;

int __sys_c2(int p0, int p1, int p2, int p3) {
    //原函数是靠r0-r7传递参数的，所以只hook前四个参数，后面不符合函数调用约定了
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "clone is call [0x%08X] [0x%08X] [0x%08X] [0x%08X]", p0, p1, p2, p3);
    return sys_ori2(p0, p1, p2, p3);
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

int my_anti_hook_proc(void *p) {
    //DUMP_CALL_STACK("lib-rev-dj");
    //注意，不能return，可能dy原来这个函数根本没打算return，以return就会crash，所以不返回就行
    sleep(10000000);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cb2 call skip!!!");
    return 0;
    //return cb2(p);
}

typedef int (*lev_type) (void *env, void *thiz, void *p1, void *p2);
lev_type lev_ori=0;
int my_lev(void *env, void *thiz, void *p1, void *p2) {
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "my_lev!!!");
    return lev_ori(env, thiz, p1, p2);
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

    MapInfo mapInfo;
    get_map_infos(&mapInfo, "libcms.so");

    /*
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cms base %p", mapInfo.baseAddr);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "cms end %p", mapInfo.endAddr);

    void *hook_anti_cb = (void*)((unsigned)mapInfo.baseAddr + 0x0005C070+1);

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook");
    MSHookFunction((void*)hook_anti_cb, (void*)my_cb, (void**)&cb);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook %p", cb);
     */


    void *lev = (void*)((unsigned)mapInfo.baseAddr + 0x0005A788+1);

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook lev");
    MSHookFunction((void*)lev, (void*)my_lev, (void**)&lev_ori);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook lev %p", lev_ori);

    //0x00065ED0 这个是反hook的函数
    //但是这样hook会导致网络登录卡住，这是由于这个函数有其他功能的原因，暂时不追究
    void *hook_anti_cb2 = (void*)((unsigned)mapInfo.baseAddr + 0x00065ED0+1);
    //0x66116 read syscall addr

    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook2");
    MSHookFunction((void *) hook_anti_cb2, (void *) my_anti_hook_proc, (void **) &cb2);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook 2 %p", cb2);

    void *syscall = (void*)((unsigned)mapInfo.baseAddr + 0x00009E7C);


    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook");
    MSHookFunction((void*)syscall, (void*)__sys_c, (void**)&sys_ori);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook %p", sys_ori);


    void *clone_call = (void*)((unsigned)mapInfo.baseAddr + 0x000189EC);
    /*
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "before hook clone");
    MSHookFunction((void*)clone_call, (void*)__sys_c2, (void**)&sys_ori2);
    __android_log_print(ANDROID_LOG_INFO, "librev-dj", "after hook clone %p", sys_ori2);
     */

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
