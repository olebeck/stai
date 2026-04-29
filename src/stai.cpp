#include "std.h"
#include "hooks.h"
#include "types.h"
#include "stubs.h"
#include "version.h"

#include <psp2kern/kernel/proc_event.h>
#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

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

static int on_process_exit(SceUID pid, SceProcEventInvokeParam1 *a2, int a3) {
  hooks::on_process_exit(pid);
  return 0;
};

static SceProcEventHandler proc_event_handler = {
  .size = sizeof(SceProcEventHandler),
  .exit = on_process_exit
};

static tai_hook_ref_t startModuleCommon_hook_ref;
static SceUID startModuleCommon_hook_id = -1;
static int startModuleCommon_hook(SceUID pid, SceUID modid, size_t args, void* argp, void* param_5, void* option, int* status) {
  hooks::before_module_start(pid, modid);
  return TAI_CONTINUEPP(startModuleCommon_hook, startModuleCommon_hook_ref, pid, modid, args, argp, param_5, option, status);
}

static tai_hook_ref_t ModulemgrDestructor_hook_ref;
static SceUID ModulemgrDestructor_hook_id = -1;
static int ModulemgrDestructor_hook(void* data) {
  SceModuleObject* module_obj = (SceModuleObject*)data;
  SceModuleCB& module_cb = module_obj->data;
  if(module_cb.pid != KERNEL_PID) {
    hooks::after_module_unload(module_cb);
  }
  return TAI_CONTINUEPP(ModulemgrDestructor_hook, ModulemgrDestructor_hook_ref, data);
}

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

  ret = hooks::init();
  LOGD("hooks::init: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  ret = ksceKernelRegisterProcEventHandler("stai_proc_event", &proc_event_handler, 0);
  LOGD("ksceKernelRegisterProcEventHandler: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  const u32 startModuleCommon_offset = 0x286C;
  ret = taiHookFunctionOffsetForKernel(
    KERNEL_PID,
    &startModuleCommon_hook_ref,
    SceKernelModulemgr_modid,
    0, startModuleCommon_offset, 1,
    (void*)startModuleCommon_hook
  );
  LOGD("taiHookFunctionOffsetForKernel: %08x", ret);
  if(ret < 0) {
    return ret;
  }
  startModuleCommon_hook_id = ret;

  SceClass* SceUIDModuleClass;
  ret = ksceKernelFindClassByName("SceUIDModuleClass", &SceUIDModuleClass);
  LOGD("ksceKernelFindClassByName: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  ret = taiHookFunctionAbs(
    KERNEL_PID,
    &ModulemgrDestructor_hook_ref,
    (void*)SceUIDModuleClass->destroy_cb,
    (void*)ModulemgrDestructor_hook
  );
  LOGD("taiHookFunctionAbs: %08x", ret);
  if(ret < 0) {
    return ret;
  }
  ModulemgrDestructor_hook_id = ret;
  return 0;
}