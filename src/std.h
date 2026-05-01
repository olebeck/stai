#ifndef _STD_H_
#define _STD_H_

#include <psp2kern/types.h>
#include <psp2kern/kernel/debug.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int u32;
typedef unsigned char u8;

int heap_init();

void* malloc(size_t size);
void free(void* ptr);
void* realloc(void* ptr, size_t size);

void abort();
int printf(const char* fmt, ...);
void __aeabi_atexit(void* obj, void (*dtor)(void*), void* dso_handle);

#ifndef LOG_LEVEL
#define LOG_LEVEL 0
#endif
#if LOG_LEVEL == OFF
#undef LOG_LEVEL
#define LOG_LEVEL 0
#endif

#define LOG(TAG, fmt, ...) do { \
  ksceKernelPrintf("[stai:" TAG "] %s " fmt "\n", __FUNCTION__, ##__VA_ARGS__); \
} while(0)

#define LOGI(fmt, ...) do { \
  if(LOG_LEVEL >= 1) { LOG("I", fmt, ##__VA_ARGS__); } \
} while(0)

#define LOGD(fmt, ...) do { \
  if(LOG_LEVEL >= 2) { LOG("D", fmt, ##__VA_ARGS__); } \
} while(0)

#define LOGE(fmt, ...) do { \
  LOG("E", fmt, ##__VA_ARGS__); \
} while(0)

#define LOG_PTR(ptr) LOGD(#ptr ": %p", ptr);

#define LOG_FUNC() LOGD("")

#define EXPORTED __attribute__((used))

#define assert(cond) \
  do { \
    if (!(cond)) { \
      ksceKernelPrintf("Assertion failed: %s, file %s, line %d\n", #cond, __FILE__, __LINE__); \
      while(1); \
    } \
  } while (0)

#define debug_assert(cond) assert(cond)

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

#ifdef __cplusplus
}
#endif

#endif
