#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

#include "std.h"
#include "hooks.h"
#include "types.h"
#include "stubs.h"
#include "version.h"

extern "C" int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, void** func);

int get_is_363(SceUID modid) {
  void* _ksceKernelGetModuleCB;
  int ret = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0xFE303863, &_ksceKernelGetModuleCB);
  if(ret < 0) {
    return 1;
  }
  return 0;
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

  ret = hooks_init(SceKernelModulemgr_modid);
  LOGD("hooks_init: %08x", ret);
  if(ret < 0) {
    return ret;
  }
  return 0;
}