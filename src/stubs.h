#ifndef _STUBS_H_
#define _STUBS_H_

#include <psp2kern/types.h>
#include "std.h"

#ifdef __cplusplus
extern "C" {
#endif

void init_363_stubs();
void* ksceKernelReallocHeapMemory(SceUID uid, void* ptr, size_t newsize);

#ifdef __cplusplus
}
#endif

#endif
