#include <psp2kern/kernel/sysmem.h>

#include "stubs.h"
#include "std.h"


static SceUID heap_uid;

int heap_init() {
  SceKernelHeapCreateOpt opt = {
    .size = sizeof(SceKernelHeapCreateOpt),
    .attr = SCE_KERNEL_HEAP_ATTR_HAS_AUTO_EXTEND
  };
  heap_uid = ksceKernelCreateHeap("staihen_heap", 0x10000, &opt);
  return heap_uid;
}

void* malloc(size_t size) {
  void* ptr = ksceKernelAllocHeapMemory(heap_uid, size);
  LOGD("size=%x ptr=%p", size, ptr);
  return ptr;
}

void free(void* ptr) {
  if(ptr == NULL) {
    return;
  }
  uint32_t lr;
  asm volatile ("mov %0, lr" : "=r" (lr));
  LOGD("ptr=%p lr=%p", ptr, lr);
  ksceKernelFreeHeapMemory(heap_uid, ptr);
}

void* realloc(void* ptr, size_t size) {
  void* new_ptr = ksceKernelReallocHeapMemory(heap_uid, ptr, size);
  LOGD("ptr=%p size=%x new_ptr=%p", ptr, size, new_ptr);
  return new_ptr;
}

void abort() {
  uint32_t lr;
  asm volatile ("mov %0, lr" : "=r" (lr));
  ksceKernelPrintf("abort lr=%p\n", lr);
  asm ("bkpt #0");
  while(1) {}
}

void __aeabi_atexit(void* obj, void (*dtor)(void*), void* dso_handle) {
  (void)obj;
  (void)dtor;
  (void)dso_handle;
}

void *__dso_handle = NULL;
