#pragma once

#include <psp2kern/types.h>
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

void hex_dump(const void* data, size_t size);

#ifdef __cplusplus
}
#endif

#define STAI_EXPORTED __attribute__((used))
