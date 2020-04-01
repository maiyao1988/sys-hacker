#include <jni.h>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <unistd.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/mman.h>

void sys_trace();
extern "C" JNIEXPORT jstring JNICALL
Java_com_reverse_my_shack_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

    sys_trace();
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

