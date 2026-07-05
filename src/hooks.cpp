#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/proc_event.h>
#include <taihen.h>

#include "../include/stai/stai.h"
#include "hooks.h"
#include "slab.h"
#include "std++.h"
#include "types.h"
#include "cpu.h"
#include "module.h"
#include "cow.h"

extern "C" {
#include "../substitute/lib/execmem.h"
#include "../substitute/lib/substitute.h"
}

#define PATCH_ITEM_SIZE (0x100)

static SceUID hook_lock = -1;

class Process;

struct Patch {
  u32 target_addr;
  substitute_function_hook_record* record;
  u32 old_func;
  Vec<User<StaiRef>> chain;

  Patch(u32 target_addr) :
    target_addr(target_addr) {}
  Patch(const Patch&) = delete;
  Patch& operator=(const Patch&) = delete;
  Patch(Patch&&) = default;
  Patch& operator=(Patch&&) = default;

  int add_hook(CtxSwitched& sw, u32 dest_func, User<StaiRef> hook_ref);
  int remove_hook(CtxSwitched& sw, Process& process, User<StaiRef> hook_ref);
  int find_ref(User<StaiRef> target);

  int remove_first(CtxSwitched& sw, Process& process);
  void remove_last(CtxSwitched& sw, int index);
  void remove_middle(CtxSwitched& sw, int index);
};

typedef SortedVec<Patch, u32, &Patch::target_addr> PatchVec;


struct PendingWrite {
  u32 dst = 0;
  u32 len = 0;
  u8 data[0x100];

  PendingWrite() = default;
  bool pending() const { return this->dst != 0; }
  int commit(CtxSwitched& sw, SceUID pid, PageRemapVec& remaps);
};

struct ModuleStartReg {
  u32 library_nid;
  u32 dest_func;
  User<StaiRef> hook_ref;

  ModuleStartReg(u32 library_nid, u32 dest_func, User<StaiRef> hook_ref) :
    library_nid(library_nid), dest_func(dest_func), hook_ref(hook_ref) {}
  ModuleStartReg(const ModuleStartReg&) = default;
  ModuleStartReg& operator=(const ModuleStartReg&) = default;
  ModuleStartReg(ModuleStartReg&&) = default;
  ModuleStartReg& operator=(ModuleStartReg&&) = default;
};

typedef SortedDupVec<ModuleStartReg, u32, &ModuleStartReg::library_nid> ModuleStartRegVec;

typedef SlabChain<PATCH_ITEM_SIZE> ProcessSlabChain;

class Process {
public:
  SceUID pid;
  ProcessSlabChain sch;
  PatchVec patches;
  PageRemapVec remaps;
  ModuleStartRegVec module_start_regs;

  Process(SceUID pid) : pid(pid) {}
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;
  Process(Process&&) = default;
  Process& operator=(Process&&) = default;

  ~Process() {
    this->pid = 0;
    for(auto& patch : this->patches) {
      if(patch.record) {
        free(patch.record);
        patch.record = nullptr;
      }
    }
  }

  void cleanup_module(const SceModuleCB& module_cb);
};

class Processes {
private:
  static int kpls_slot;
public:
  Processes() = default;

  static int init() {
    kpls_slot = ksceKernelCreateProcessLocalStorage("stai_process", sizeof(Process));
    LOGD("ksceKernelCreateProcessLocalStorage: %d", kpls_slot);
    return kpls_slot;
  }

  static Process* get(SceUID pid) {
    Process* process = nullptr;
    ksceKernelGetProcessLocalStorageAddrForPid(pid, kpls_slot, (void**)&process, 0);
    if(process == nullptr || process->pid == 0) {
      return nullptr;
    }
    return process;
  }

  static Process* get_or_create(SceUID pid) {
    Process* process = nullptr;
    ksceKernelGetProcessLocalStorageAddrForPid(pid, kpls_slot, (void**)&process, 1);
    if(process && process->pid == 0) {
      process = new(process) Process(pid);
    }
    return process;
  }

  static void cleanup(SceUID pid) {
    Process* process = Processes::get(pid);
    if(process && process->pid != 0) {
      process->~Process();
    }
  }
};

int Processes::kpls_slot = -1;

int HookLocation::resolve(CtxSwitched& sw, u32& ptr) const {
  SceModuleCB* module_cb;
  int ret = ksceKernelGetModuleCB(this->module_uid, (void**)&module_cb);
  if(ret < 0) {
    return ret;
  }
  SceSegmentInfoInternal* seg = &module_cb->segments.segments[0];
  switch(this->type) {
    case Type::Offset: {
      ptr = (u32)seg->base_addr + this->offset.offset;
      break;
    }
    case Type::Import: {
      ret = module_cb_get_import_func(sw, *module_cb, this->nid.library_nid, this->nid.func_nid, ptr);
      if(ret == 0) {
        u32 stub[3];
        ksceKernelCopyFromUser(stub, (void*)(ptr & ~1), sizeof(stub));
        if(stub[0] == 0xE24FC008 && stub[1] == 0xE12FFF1E) {
          LOGD("stub for %p has not been resolved yet!", this->nid.func_nid);
          return STAI_ERROR_STUB_NOT_RESOLVED;
        }
      }
      break;
    }
    case Type::Export: {
      ret = module_cb_get_export_func(sw, *module_cb, this->nid.library_nid, this->nid.func_nid, ptr);
      break;
    }
    default: {
      ret = STAI_ERROR_INVALID_ARGS;
    }
  }

  u32 start = (u32)seg->base_addr;
  u32 end = start + seg->memsz;
  if(ptr < start || ptr > end) {
    LOGD("start=%08x end=%08x size=0x%x ptr=%08x out of bounds", start, end, seg->memsz, ptr);
    return STAI_ERROR_NOT_FOUND;
  }
  return 0;
}

int PendingWrite::commit(CtxSwitched& sw, SceUID pid, PageRemapVec& remaps) {
  return write_user_text(sw, pid, remaps, this->dst, this->data, this->len);
}

struct ExecmemCtx {
  CtxSwitched& sw;
  SceUID pid;
  ProcessSlabChain* sch;
  PendingWrite pending_write;
  ExecmemCtx(CtxSwitched& sw, SceUID pid, ProcessSlabChain* sch) : sw(sw), pid(pid), sch(sch) {}
};

extern "C" int execmem_alloc_unsealed(u32 hint, void** ptr, u32* vma, u32* size, void* opt) {
  ExecmemCtx* ctx = (ExecmemCtx*)opt;
  *ptr = ctx->sch->alloc(ctx->pid, vma);
  if(*ptr) {
    *size = PATCH_ITEM_SIZE;
    return SUBSTITUTE_OK;
  }
  return STAI_ERROR_OOM;
}

extern "C" int execmem_seal(void* ptr, void* opt) {
  ExecmemCtx* ctx = (ExecmemCtx*)opt;
  u32 vma = ctx->sch->getmirror(ptr);
  cache_flush_kernel((u32)ptr, PATCH_ITEM_SIZE);
  cache_flush_user(ctx->sw, vma, PATCH_ITEM_SIZE);
  return SUBSTITUTE_OK;
}

extern "C" void execmem_free(void* ptr, void* opt) {
  ExecmemCtx* ctx = (ExecmemCtx*)opt;
  ctx->sch->free(ptr);
}

extern "C" int execmem_foreign_write_with_pc_patch(struct execmem_foreign_write* writes, size_t nwrites, execmem_pc_patch_callback callback, void* callback_ctx) {
  (void)callback;
  (void)callback_ctx;
  execmem_foreign_write* write = &writes[0];
  LOGD("dst=%08x, src=%p, len=%d", write->dst, write->src, write->len);

  ExecmemCtx* ctx = (ExecmemCtx*)write->opt;
  ctx->pending_write.dst = (u32)write->dst;
  ctx->pending_write.len = write->len;
  debug_assert(write->len < sizeof(ctx->pending_write.data));
  memcpy(ctx->pending_write.data, write->src, write->len);
  return SUBSTITUTE_OK;
}

int patch_function(CtxSwitched& sw, Process& process, Patch& patch, u32 dest_func, User<StaiRef> hook_ref) {
  LOG_FUNC();
  ExecmemCtx ctx(sw, process.pid, &process.sch);

  struct hook_args {
    struct substitute_function_hook hook;
    struct substitute_function_hook_record** record;
    SceUID pid;
    int ret;
  } args{
    .hook = {
      .function = (void*)patch.target_addr,
      .replacement = (void*)dest_func,
      .old_ptr = (void**)&patch.old_func,
      .options = 0,
      .opt = &ctx
    },
    .record = &patch.record,
    .pid = process.pid,
    .ret = -1
  };

  ksceKernelRunWithStack(0x4000, [](void* userarg) {
    hook_args* args = (hook_args*)userarg;
    SwitchCtx ctx(args->pid);
#ifdef DEBUG
    LOGD("target_addr: %08x", args->hook.function);
    hex_dump((void*)((u32)args->hook.function & ~1), 0x20);
#endif
    args->ret = substitute_hook_functions(&args->hook, 1, args->record, SUBSTITUTE_RELAXED);
    return 0;
  }, &args);
  if(args.ret != SUBSTITUTE_OK) {
    LOGD("substitute_hook_functions failed: %08x (%s)", args.ret, substitute_strerror(args.ret));
    return STAI_ERROR_BASE + args.ret;
  }

  hook_ref.write(sw, StaiRef{
    .next = nullptr,
    .func = dest_func,
    .old = patch.old_func,
    .target_addr = patch.target_addr,
  });
  if(patch.chain.emplace_back(hook_ref) == nullptr) {
    return STAI_ERROR_MEMORY;
  }

  if(ctx.pending_write.pending()) {
    int ret = ctx.pending_write.commit(sw, process.pid, process.remaps);
    if(ret < 0) {
      return ret;
    }
  }
  return 0;
}

int unpatch_function(CtxSwitched& sw, Process& process, Patch& patch) {
  LOG_FUNC();
  if(patch.record == nullptr) {
    return STAI_ERROR_UNEXPECTED;
  }
  int ret = write_user_text(sw, process.pid, process.remaps, (u32)patch.record->function, (u8*)patch.record->saved_buffer, patch.record->buffer_size);
  free(patch.record);
  patch.record = nullptr;
  return ret;
}

void Process::cleanup_module(const SceModuleCB& module_cb) {
  const u32 text_start = (u32)module_cb.segments.segments[0].base_addr;
  const u32 text_end = text_start + module_cb.segments.segments[0].memsz;

  // free patch records, dont need to rewrite because the module is being deleted
  auto patch_slice = this->patches.slice(text_start, text_end);
  if(patch_slice.len) {
    LOGD("module %s text range: %08x-%08x patches=%d", module_cb.module_name, text_start, text_end, patch_slice.len);

    SwitchCtx ctx(module_cb.pid);
    for(Patch& patch : patch_slice) {
      if(patch.record) {
        int ret = unpatch_function(ctx, *this, patch);
        (void)(ret);
        LOGD("unpatch_function: %08x", ret);
      }
    }
    this->patches.erase_slice(patch_slice);
  }

  // clean page remaps, restore original page entries
  auto remap_slice = this->remaps.slice(text_start, text_end);
  if(remap_slice.len) {
    restore_pages(module_cb.pid, remap_slice);
    this->remaps.erase_slice(remap_slice);
  }
}

int Patch::add_hook(CtxSwitched& sw, u32 dest_func, User<StaiRef> hook_ref) {
  LOG_FUNC();
  for(auto& ref2 : this->chain) {
    if(ref2 == hook_ref) {
      return STAI_ERROR_INVALID_ARGS;
    }
  }

  hook_ref.write(sw, StaiRef{
    .next = nullptr,
    .func = dest_func,
    .old = this->old_func,
    .target_addr = this->target_addr
  });
  if(this->chain.emplace_back(hook_ref) == nullptr) {
    return STAI_ERROR_OOM;
  }

  User<StaiRef> prev = this->chain[this->chain.size() - 2];
  StaiRef prev_ref = prev.read(sw);
  prev_ref.next = hook_ref;
  prev_ref.old = 0;
  prev.write(sw, prev_ref);
  return 0;
}

int Patch::find_ref(User<StaiRef> target) {
  size_t chain_len = this->chain.size();
  for(size_t i = 0; i < chain_len; i++) {
    User<StaiRef> ref2 = this->chain[i];
    if(ref2 == target) {
      return i;
    }
  }
  return -1;
}

int Patch::remove_first(CtxSwitched& sw, Process& process) {
  StaiRef next_ref = this->chain.front()->read(sw);
  User<StaiRef> tail = *this->chain.back();

  int ret = unpatch_function(sw, process, *this);
  if(ret < 0) {
    return ret;
  }
  ret = patch_function(sw, process, *this, next_ref.func, tail);
  this->chain.erase(0);
  return ret;
}

void Patch::remove_middle(CtxSwitched& sw, int index) {
  auto prev = this->chain[index - 1];
  StaiRef prev_ref = prev.read(sw);
  prev_ref.next = this->chain[index + 1];
  prev.write(sw, prev_ref);
  this->chain.erase(index);
}

void Patch::remove_last(CtxSwitched& sw, int index) {
  User<StaiRef> prev = this->chain[index - 1];
  StaiRef prev_ref = prev.read(sw);
  prev_ref.next = nullptr;
  prev_ref.old = this->old_func;
  prev.write(sw, prev_ref);
  this->chain.erase(index);
}

int Patch::remove_hook(CtxSwitched& sw, Process& process, User<StaiRef> hook_ref) {
  LOG_FUNC();
  int index = this->find_ref(hook_ref);
  if(index < 0) {
    return STAI_ERROR_INVALID_ARGS;
  }

  // is first
  if(index == 0) {
    // and is last
    if(this->chain.size() == 1) {
      int ret = unpatch_function(sw, process, *this);
      this->chain.erase(index);
      return ret;
    }
    return this->remove_first(sw, process);
  }

  // is last
  if((size_t)index == this->chain.size() - 1) {
    this->remove_last(sw, index);
    return 0;
  }

  // in the middle
  this->remove_middle(sw, index);
  return 0;
}

int hook_function(CtxSwitched& sw, SceUID pid, const HookLocation& location, u32 dest_func, User<StaiRef> hook_ref) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Process* process = Processes::get_or_create(pid);
  if(!process) {
    return STAI_ERROR_OOM;
  }

  u32 target_addr = 0;
  int ret = location.resolve(sw, target_addr);
  if(ret < 0) {
    LOGD("failed to resolve hook location: %08x", ret);
    return ret;
  }
  if(target_addr == 0) {
    return STAI_ERROR_NOT_FOUND;
  }

  auto find = process->patches.find(target_addr);
  if(find.is_found()) {
    Patch& patch = process->patches[find.index()];
    return patch.add_hook(sw, dest_func, hook_ref);
  }

  Patch* patch = process->patches.emplace_at(find, target_addr);
  if(!patch) {
    return STAI_ERROR_OOM;
  }
  ret = patch_function(sw, *process, *patch, dest_func, hook_ref);
  if(ret < 0) {
    process->patches.erase(find);
    return ret;
  }
  return 0;
}

int hook_module_start(SceUID pid, u32 library_nid, u32 dest_func, User<StaiRef> hook_ref) {
  ScopeLock lock(hook_lock);
  Process* process = Processes::get_or_create(pid);
  if(!process) {
    return STAI_ERROR_OOM;
  }
  if(process->module_start_regs.emplace(library_nid, dest_func, hook_ref) == nullptr) {
    LOGD("failed to emplace module start reg for library_nid 0x%08x", library_nid);
    return STAI_ERROR_OOM;
  }
  return 0;
}

int unhook_function(CtxSwitched& sw, SceUID pid, User<StaiRef> hook_ref) {
  ScopeLock lock(hook_lock);
  Process* process = Processes::get_or_create(pid);
  if(!process) {
    return STAI_ERROR_OOM;
  }
  u32 target_addr = hook_ref.read(sw).target_addr;
  if(target_addr == 0) {
    return STAI_ERROR_INVALID_ARGS;
  }
  auto find = process->patches.find(target_addr);
  if(!find.is_found()) {
    return STAI_ERROR_INVALID_ARGS;
  }
  Patch& patch = process->patches[find.index()];
  int ret = patch.remove_hook(sw, *process, hook_ref);
  if(ret < 0) {
    return ret;
  }
  if(patch.chain.size() == 0) {
    process->patches.erase(find);
  }
  return 0;
}

void module_start_hook_make_chain(const SceModuleCB& module_cb, void*& new_module_start) {
  ScopeLock lock(hook_lock);
  Process* process = Processes::get(module_cb.pid);
  if(!process) {
    return;
  }

  SwitchCtx ctx(module_cb.pid);

  ModuleStartReg* first = nullptr;
  ModuleStartReg* prev = nullptr;
  for(size_t i = 0; i < module_cb.lib_export_num; i++) {
    sce_module_exports* exp = &module_cb.exports[i];
    for(auto& reg : process->module_start_regs.slice(exp->lib_nid)) {
      if(first == nullptr) {
        first = &reg;
      }
      User<StaiRef> next = prev ? prev->hook_ref : nullptr;
      LOGD("write ref next=%p func=%p old=%p", next, reg.dest_func, module_cb.module_start);
      reg.hook_ref.write(ctx, StaiRef{
        .next = next,
        .func = reg.dest_func,
        .old = (u32)module_cb.module_start
      });
      prev = &reg;
    }
  }
  if(first) {
    new_module_start = (void*)first->dest_func;
  }
}

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

#define TAI_HOOK_CONTINUE(name, ...) TAI_CONTINUEPP(name ## _hook, name ## _hook_ref, __VA_ARGS__)

#define TAI_HOOK_OFFSET(modid, name, offset) \
  ret = taiHookFunctionOffsetForKernel(KERNEL_PID, &name ## _hook_ref, modid, 0, offset, 1, (void*)name ## _hook); \
  LOGD("taiHookFunctionOffsetForKernel(" #name "): %08x", ret); \
  if(ret < 0) { \
    return ret; \
  } \
  name ## _hook_id = ret;

#define TAI_HOOK(typ, name, ...) \
  static tai_hook_ref_t name ## _hook_ref; \
  static SceUID name ## _hook_id = -1; \
  static typ name ## _hook(__VA_ARGS__) 

TAI_HOOK(int, ModulemgrDestructor, void* data) {
  SceModuleObject* module_obj = (SceModuleObject*)data;
  const SceModuleCB& module_cb = module_obj->data;
  if(module_cb.pid != KERNEL_PID) {
    ScopeLock lock(hook_lock);
    Process* process = Processes::get(module_cb.pid);
    if(process) {
      process->cleanup_module(module_cb);
    }
  }
  return TAI_HOOK_CONTINUE(ModulemgrDestructor, data);
}

TAI_HOOK(int, startModuleCommon, SceUID pid, SceUID modid, size_t argc, void* argv, void* param_5, void* option, int* status) {
  if(pid == KERNEL_PID) {
    return TAI_HOOK_CONTINUE(startModuleCommon, pid, modid, argc, argv, param_5, option, status);
  }

  SceModuleCB* module_cb;
  int ret = ksceKernelGetModuleCB(modid, (void**)&module_cb);
  if(ret < 0) {
    return ret;
  }
  void* new_module_start = nullptr;
  module_start_hook_make_chain(*module_cb, new_module_start);

  void* real_module_start = module_cb->module_start;
  if(new_module_start) {
    module_cb->module_start = new_module_start;
  }
  ret = TAI_HOOK_CONTINUE(startModuleCommon, pid, modid, argc, argv, param_5, option, status);
  module_cb->module_start = real_module_start;
  return ret;
}

TAI_HOOK(int, ModulemgrStopModule, SceUID pid, SceUID modid, int argc, void* argv, void* param_5, void* option, int* status) {
  if(pid != KERNEL_PID) {
    ScopeLock lock(hook_lock);
    Process* process = Processes::get(pid);
    if(process) {
      SceModuleCB* module_cb;
      int ret = ksceKernelGetModuleCB(modid, (void**)&module_cb);
      if(ret < 0) {
        return ret;
      }
      process->cleanup_module(*module_cb);
    }
  }
  return TAI_HOOK_CONTINUE(ModulemgrStopModule, pid, modid, argc, argv, param_5, option, status);
}

TAI_HOOK(int, unlink_imports, void* stublinker) {
  int ret = TAI_HOOK_CONTINUE(unlink_imports, stublinker);
  LOGD("unlink_imports: %08x", ret);
  return ret;
}

static int on_process_exit(SceUID pid, SceProcEventInvokeParam1 *a2, int a3) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Processes::cleanup(pid);
  return 0;
};

static int on_process_kill(SceUID pid, SceProcEventInvokeParam1 *a2, int a3) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Processes::cleanup(pid);
  return 0;
};

static SceProcEventHandler proc_event_handler = {
  .size = sizeof(SceProcEventHandler),
  .exit = on_process_exit,
  .kill = on_process_kill,
};

int hooks_init() {
  Processes::init();
  hook_lock = ksceKernelCreateMutex("stai_hook_lock", 0, 0, nullptr);

  int ret = ksceKernelRegisterProcEventHandler("stai_proc_event", &proc_event_handler, 0);
  LOGD("ksceKernelRegisterProcEventHandler: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  ret = ksceKernelSearchModuleByName("SceKernelModulemgr");
  LOGD("ksceKernelSearchModuleByName(SceKernelModulemgr): %08x", ret);
  if(ret < 0) {
    return ret;
  }
  SceUID SceKernelModulemgr_modid = ret;

  SceClass* SceUIDModuleClass;
  ret = ksceKernelFindClassByName("SceUIDModuleClass", &SceUIDModuleClass);
  LOGD("ksceKernelFindClassByName: %08x", ret);
  if(ret < 0) {
    return ret;
  }

  ret = taiHookFunctionAbs(KERNEL_PID, &ModulemgrDestructor_hook_ref, (void*)SceUIDModuleClass->destroy_cb, (void*)ModulemgrDestructor_hook);
  LOGD("taiHookFunctionAbs(ModulemgrDestructor): %08x", ret);
  if(ret < 0) {
    return ret;
  }
  ModulemgrDestructor_hook_id = ret;

  TAI_HOOK_OFFSET(SceKernelModulemgr_modid, startModuleCommon, 0x286C);
  TAI_HOOK_OFFSET(SceKernelModulemgr_modid, ModulemgrStopModule, 0x2b40);
  TAI_HOOK_OFFSET(SceKernelModulemgr_modid, unlink_imports, 0x5620)

  return 0;
}
