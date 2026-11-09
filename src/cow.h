#pragma once

#include <psp2kern/types.h>

#include "runtime.h"

namespace stai::cow {

int init();

SceUID write(SceUID pid, u32 addr, const u8* data, u32 len);

int release(SceUID uid);

int release_range(SceUID pid, u32 start, u32 end, bool write_back);

void cleanup(SceUID pid);

void dump_state(SceUID pid);

} // namespace stai::cow
