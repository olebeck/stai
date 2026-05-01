#include <psp2kern/kernel/modulemgr.h>

#include "std.h"
#include "hooks.h"
#include "types.h"
#include "stubs.h"
#include "version.h"


int get_is_363(SceUID modid) {
  SceModuleCB* SceKernelModulemgr;
  int ret = ksceKernelGetModuleCB(modid, (void**)&SceKernelModulemgr);
  LOGD("ksceKernelGetModuleCB(SceKernelModulemgr): %08x", ret);
  if(ret < 0) {
    return ret;
  }
  u8* cur = (u8*)SceKernelModulemgr->libent_top;
  while(cur < (u8*)SceKernelModulemgr->libent_btm) {
    SceModuleExport* exp = (SceModuleExport*)cur;
    if(exp->library_nid == 0xC445FA63) {
      return 0;
    }
    if(exp->library_nid == 0x92C9FFC2) {
      return 1;
    }
    cur += exp->size;
  }
  return -1;
}

extern "C" EXPORTED int module_start(SceSize argc, const void* argv) {
  int ret;

  LOGI(GIT_COMMIT " starting");
#ifdef STAI_VERSION
  LOGI("version: " STAI_VERSION);
#endif

  ret = ksceKernelSearchModuleByName("SceKernelModulemgr");
  LOGD("ksceKernelSearchModuleByName(SceKernelModulemgr): %08x", ret);
  if(ret < 0) {
    return ret;
  }
  SceUID SceKernelModulemgr_modid = ret;

  ret = get_is_363(SceKernelModulemgr_modid);
  LOGD("get_is_363: %08x", ret);
  if(ret < 0) {
    return ret;
  }
  if(ret == 1) {
    LOGD("running on >3.63");
    init_363_stubs();
  }

  ret = heap_init();
  LOGD("heap_init: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  ret = hooks::init(SceKernelModulemgr_modid);
  LOGD("hooks::init: %08x", ret);
  if(ret < 0) {
    return ret;
  }
  return 0;
}