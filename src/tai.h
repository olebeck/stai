#pragma once

#include <taihen.h>

#include "log.h"

#define TAI_CONTINUEPP(fn, hook, ...) ({ \
    struct _tai_hook_user *cur, *next; \
    cur = (struct _tai_hook_user *)(hook); \
    next = (struct _tai_hook_user *)cur->next; \
    typedef __typeof__(fn) *_fn_ptr_type; \
        (next == NULL)  ? \
        ((_fn_ptr_type)(cur->old))(__VA_ARGS__) \
    : \
        ((_fn_ptr_type)(next->func))(__VA_ARGS__) \
    ; \
})

#define TAI_HOOK_CONTINUE(name, ...) TAI_CONTINUEPP(name ## _hook, name ## _hook_ref, __VA_ARGS__)

#define TAI_HOOK_OFFSET(modid, name, offset) \
    ret = taiHookFunctionOffsetForKernel(KERNEL_PID, &name ## _hook_ref, modid, 0, offset, 1, reinterpret_cast<void*>(name ## _hook)); \
    ::stai::log::debug("taiHookFunctionOffsetForKernel(" #name "): %08x", ret); \
    if(ret < 0) { \
        return ret; \
    } \
    name ## _hook_id = ret;

#define TAI_HOOK(typ, name, ...) \
    static tai_hook_ref_t name ## _hook_ref; \
    static SceUID name ## _hook_id = -1; \
    static typ name ## _hook(__VA_ARGS__)
