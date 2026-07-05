#include "module.h"

static int find_nid_user(CtxSwitched&, u32* nids, void** ents, u32 count, u32 nid, u32& out_ent) {
  Dacr dacr(0x55555555);
  for(u32 i = 0; i < count; i++) {
    u32 ent_nid;
    asm("ldrt %0, [%1]" : "=r" (ent_nid) : "r" (nids+i));
    if(ent_nid == nid) {
      asm("ldrt %0, [%1]" : "=r" (out_ent) : "r" (ents+i));
      return 0;
    }
  }
  return -1;
}

int librarydb_get_module_by_library_nid(SceUID pid, u32 library_nid, SceModuleCB*& out_module) {
  SceKernelLibraryDB* libdb = (SceKernelLibraryDB*)ksceKernelGetProcessModuleInfo(pid);
  SceKernelIntrStatus intr = ksceKernelSpinlockLowLockCpuSuspendIntr(&libdb->mutex);
  ksceGUIDReleaseObject(pid);
  SceModuleLibEnt* ent = libdb->lib_ents;
  while(ent) {
    if(ent->exports->lib_nid == library_nid) {
      ksceKernelSpinlockLowUnlockCpuResumeIntr(&libdb->mutex, intr);
      out_module = ent->module_cb;
      return 0;
    }
    ent = ent->next;
  }
  ksceKernelSpinlockLowUnlockCpuResumeIntr(&libdb->mutex, intr);
  return 0x8002d081;
}

int module_cb_get_export_func(CtxSwitched& sw, const SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32& out_func) {
  u32 cur = module_cb.libent_top;
  while(cur < module_cb.libent_btm) {
    sce_module_exports_t exp = copy_from_user(sw, (sce_module_exports_t*)cur);
    if(library_nid == 0xffffffff || exp.lib_nid == library_nid) {
      if(find_nid_user(sw, exp.nid_table, exp.entry_table, exp.num_functions, func_nid, out_func) == 0) {
        return 0;
      }
    }
    cur += exp.size;
  }
  return 0x8002d081;
}

int module_cb_get_import_func(CtxSwitched& sw, const SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32& out_func) {
  u32 cur = module_cb.libstub_top;
  while(cur < module_cb.libstub_btm) {
    uint16_t size = copy_from_user(sw, (uint16_t*)cur);
    switch(size) {
      case sizeof(sce_module_imports_1): {
        sce_module_imports_1 import = copy_from_user(sw, (sce_module_imports_1*)cur);
        if(library_nid == 0xffffffff || import.lib_nid == library_nid) {
          if(find_nid_user(sw, import.func_nid_table, import.func_entry_table, import.num_functions, func_nid, out_func) == 0) {
            return 0;
          }
        }
        break;
      }
      case sizeof(sce_module_imports_2): {
        sce_module_imports_2 import = copy_from_user(sw, (sce_module_imports_2*)cur);
        if(library_nid == 0xffffffff || import.lib_nid == library_nid) {
          if(find_nid_user(sw, import.func_nid_table, import.func_entry_table, import.num_functions, func_nid, out_func) == 0) {
            return 0;
          }
        }
        break;
      }
      default: {
        LOGE("skipping unknown import format size=%d", size);
      }
    }
    cur += size;
  }
  return 0x8002d081;
}
