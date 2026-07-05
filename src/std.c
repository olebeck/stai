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
#ifdef DEBUG
  uint32_t lr;
  asm volatile ("mov %0, lr" : "=r" (lr));
  LOGD("size=%x ptr=%p lr=%p", size, ptr, lr);
#endif
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

void hex_dump(const void* data, size_t size) {
  const u8* bytes = (const u8*)data;
  for(size_t i = 0; i < size; i++) {
    if(i % 16 == 0) {
      ksceKernelPrintf("%08x: ", (u32)(bytes + i));
    }
    ksceKernelPrintf("%02x ", bytes[i]);
    if(i % 16 == 15 || i == size - 1) {
      ksceKernelPrintf("\n");
    }
  }
}
