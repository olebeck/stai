#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>

#include "runtime.h"

#if !defined(NDEBUG) && !defined(STAI_DEBUG)
#define STAI_DEBUG
#endif

#ifdef STAI_DEBUG
#define RUNTIME_LOG(fmt, ...) ksceKernelPrintf("[stai:D] " fmt "\n", ##__VA_ARGS__)
#else
#define RUNTIME_LOG(...) ((void)0)
#endif

static SceUID heap_uid;

int heap_init() {
    SceKernelHeapCreateOpt opt = {
        .size = sizeof(SceKernelHeapCreateOpt),
        .attr = SCE_KERNEL_HEAP_ATTR_HAS_AUTO_EXTEND,
    };
    heap_uid = ksceKernelCreateHeap("staihen_heap", 0x10000, &opt);
    return heap_uid;
}

void* malloc(size_t size) {
    void* ptr = ksceKernelAllocHeapMemory(heap_uid, size);
#ifdef STAI_DEBUG
    uint32_t lr;
    asm volatile ("mov %0, lr" : "=r"(lr));
    RUNTIME_LOG("size=%x ptr=%p lr=%p", size, ptr, lr);
#endif
    return ptr;
}

void free(void* ptr) {
    if(ptr == NULL) {
        return;
    }
#ifdef STAI_DEBUG
    uint32_t lr;
    asm volatile ("mov %0, lr" : "=r"(lr));
    RUNTIME_LOG("ptr=%p lr=%p", ptr, lr);
#endif
    ksceKernelFreeHeapMemory(heap_uid, ptr);
}

void* realloc(void* ptr, size_t size) {
    void* new_ptr = ksceKernelReallocHeapMemory(heap_uid, ptr, size);
    RUNTIME_LOG("ptr=%p size=%x new_ptr=%p", ptr, size, new_ptr);
    return new_ptr;
}

void abort() {
    uint32_t lr;
    asm volatile ("mov %0, lr" : "=r"(lr));
    ksceKernelPrintf("abort lr=%p\n", lr);
    asm ("bkpt #0");
    while(1) {}
}

void __aeabi_atexit(void* obj, void (*dtor)(void*), void* dso_handle) {
    (void)obj;
    (void)dtor;
    (void)dso_handle;
}

void* __dso_handle = NULL;

void hex_dump(const void* data, size_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    for(size_t i = 0; i < size; i++) {
        if(i % 16 == 0) {
            ksceKernelPrintf("%08x: ", (uint32_t)(bytes + i));
        }
        ksceKernelPrintf("%02x ", bytes[i]);
        if(i % 16 == 15 || i == size - 1) {
            ksceKernelPrintf("\n");
        }
    }
}
