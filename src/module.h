#pragma once

#include <psp2kern/kernel/processmgr.h>

#include "std++.h"
#include "cpu.h"
#include "types.h"

int librarydb_get_module_by_library_nid(SceUID pid, u32 library_nid, SceModuleCB*& out_module);

int module_cb_get_export_func(CtxSwitched&, const SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32& out_func);

int module_cb_get_import_func(CtxSwitched&, const SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32& out_func);
