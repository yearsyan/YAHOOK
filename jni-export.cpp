#include <jni.h>
#include <android/log.h>
#include "hook.h"

/*
 * package io.github.yearsyan;
 *
 * public class YAHOOK {
 *   private long hookContext;
 *   public YAHOOK() {
 *       init();
 *   }
 *   public native void init();
 *   public native void release();
 *   public native void hook(long origin_func, long new_func);
 * }
 *
 *
 * */

#define EXPORT_CLASS "io/github/yearsyan/YAHOOK"
#define METHOD_ITEM(name, sig) {#name, sig, (void*)YAHOOK_##name}


static void YAHOOK_init(JNIEnv *env, jobject thiz) {
    auto YAHOOK_class = env->GetObjectClass(thiz);
    auto YAHOOK_context_field = env->GetFieldID(YAHOOK_class, "hookContext", "J");
    auto ctx = new hook::context;
    env->SetLongField(thiz, YAHOOK_context_field, reinterpret_cast<jlong>(ctx));
}

static void YAHOOK_release(JNIEnv *env, jobject thiz) {
    auto YAHOOK_class = env->GetObjectClass(thiz);
    auto YAHOOK_context_field = env->GetFieldID(YAHOOK_class, "hookContext", "J");
    auto ctx = reinterpret_cast<hook::context*>(env->GetLongField(thiz, YAHOOK_context_field));
    delete ctx;
}

static void YAHOOK_hook(JNIEnv *env, jobject thiz, jlong origin_func, jlong new_func) {
    auto YAHOOK_class = env->GetObjectClass(thiz);
    auto YAHOOK_context_field = env->GetFieldID(YAHOOK_class, "hookContext", "J");
    auto ctx = reinterpret_cast<hook::context*>(env->GetLongField(thiz, YAHOOK_context_field));
    ctx->hook(reinterpret_cast<void *>(origin_func), reinterpret_cast<void *>(new_func));
}

static JNINativeMethod exportMethods[] = {
        METHOD_ITEM(hook, "(JJ)V"),
        METHOD_ITEM(release, "()V"),
        METHOD_ITEM(init, "()V"),
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {

    JNIEnv *env = nullptr;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    if(env->RegisterNatives(
            env->FindClass(EXPORT_CLASS),
            exportMethods,
            sizeof(exportMethods)/ sizeof(JNINativeMethod)
    ) != JNI_OK) {
        return -1;
    }

    return JNI_VERSION_1_6;
}
