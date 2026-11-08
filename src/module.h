#pragma once

#include <psp2kern/kernel/processmgr.h>

#include "cpu.h"
#include "types.h"

namespace stai::modules {

int find_module_by_library_nid(SceUID pid, u32 library_nid, ModuleCB*& out_module);

int find_export_func(const ModuleCB& module, u32 library_nid, u32 func_nid, u32& out_func);

int find_import_func(const ModuleCB& module, u32 library_nid, u32 func_nid, u32& out_func);

} // namespace stai::modules
