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

extern "C" {
#include "../substitute/lib/execmem.h"
#include "../substitute/lib/substitute.h"
}

#define PATCH_ITEM_SIZE (0x100)

static SceUID hook_lock = -1;

struct Patch;
struct PageRemap;
struct PendingWrite;
struct ModuleStartReg;
struct ModuleStartPatch;
class Process;
class Processes;
struct HookLocation;

struct StaiRef {
  User<StaiRef> next;
  u32 func;
  u32 old;
  u32 target_addr;
  StaiRef() = default;
};

struct Patch {
  u32 target_addr;
  substitute_function_hook_record* record;
  u32 old_func;
  Vec<User<StaiRef>> chain;

  Patch(u32 target_addr) : target_addr(target_addr) {}
  Patch(const Patch&) = delete;
  Patch& operator=(const Patch&) = delete;
  Patch(Patch&&) = default;
  Patch& operator=(Patch&&) = default;

  int add_hook(CtxSwitched sw, u32 dest_func, User<StaiRef> hook_ref);
  int remove_hook(CtxSwitched sw, Process* process, User<StaiRef> hook_ref);
};

typedef SortedVec<Patch, u32, &Patch::target_addr> PatchVec;

struct PageRemap {
  u32 target_vaddr;
  SceUID block_uid;

  PageRemap(u32 target_vaddr, SceUID block_uid) : target_vaddr(target_vaddr), block_uid(block_uid) {}
  PageRemap(const PageRemap&) = delete;
  PageRemap& operator=(const PageRemap&) = delete;
  PageRemap(PageRemap&&) = default;
  PageRemap& operator=(PageRemap&&) = default;
};

typedef SortedVec<PageRemap, u32, &PageRemap::target_vaddr> PageRemapVec;

struct PendingWrite {
  u32 dst = 0;
  u32 len = 0;
  u8 data[0x100];

  PendingWrite() = default;
  bool pending() const { return this->dst != 0; }
  int commit(CtxSwitched sw, SceUID pid, PageRemapVec& remaps);
};

struct ModuleStartReg {
  u32 library_nid;
  u32 dest_func;
  User<StaiRef> hook_ref;

  ModuleStartReg(u32 library_nid, u32 dest_func, User<StaiRef> hook_ref) : library_nid(library_nid), dest_func(dest_func), hook_ref(hook_ref) {}
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

  void cleanup_module(SceModuleCB& module_cb);
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

struct HookLocation {
  enum class Type {
    Offset,
    Import,
    Export
  };

  SceUID module_uid;
  Type type;
  union {
    u32 offset;
    struct {
      u32 library_nid;
      u32 func_nid;
    } nid;
  };

  int resolve(CtxSwitched sw, u32* ptr);
};

void hex_dump(const void* data, size_t size) {
  const u8* bytes = (const u8*)data;
  for(size_t i = 0; i < size; i++) {
    if(i % 16 == 0) {
      ksceKernelPrintf("%08x: ", (u32)(bytes + i));
    }
    ksceKernelPrintf("%02x ", bytes[i]);
    if(i % 16 == 15 || i == size - 1) {
      ksceKernelPrintf("\n");
    }
  }
}

int module_cb_get_export_func(CtxSwitched, SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32* p_func) {
  u8* cur = (u8*)module_cb.libent_top;
  while(cur) {
    SceModuleExport exp;
    ksceKernelCopyFromUser(&exp, cur, sizeof(exp));
    if(library_nid == 0xffffffff || exp.library_nid == library_nid) {
      for(u32 i = 0; i < exp.num_function; i++) {
        if(exp.nid_vec[i] == func_nid) {
          *p_func = (u32)exp.entry_vec[i];
          return 0;
        }
      }
    }
    cur += exp.size;
  }
  return 0x8002d081;
}

int module_cb_get_import_func(CtxSwitched, SceModuleCB& module_cb, u32 library_nid, u32 func_nid, u32* p_func) {
  u8* cur = (u8*)module_cb.libstub_top;
  while(cur < (u8*)module_cb.libstub_btm) {
    size_t size;
    ksceKernelCopyFromUser(&size, cur, 4);
    
    uint32_t import_library_nid;
    uint32_t num_function;
    uint32_t* func_nid_vec;
    void** func_entry_vec;
    if(size == sizeof(SceModuleImport1)) {
      SceModuleImport1 import;
      ksceKernelCopyFromUser(&import, cur, sizeof(import));
      import_library_nid = import.library_nid;
      num_function = import.num_function;
      func_nid_vec = import.func_nid_vec;
      func_entry_vec = import.func_entry_vec;
    } else if(size == sizeof(SceModuleImport2)) {
      SceModuleImport2 import;
      ksceKernelCopyFromUser(&import, cur, sizeof(import));
      import_library_nid = import.library_nid;
      num_function = import.num_function;
      func_nid_vec = import.func_nid_vec;
      func_entry_vec = import.func_entry_vec;
    } else {
      LOGE("skipping unknown import format size=%d", size);
      cur += size;
      continue;
    }
    if(library_nid == 0xffffffff || import_library_nid == library_nid) {
      for(u32 i = 0; i < num_function; i++) {
        if(func_nid_vec[i] == func_nid) {
          *p_func = (u32)func_entry_vec[i];
          return 0;
        }
      }
    }
    cur += size;
  }
  return 0x8002d081;
}

int HookLocation::resolve(CtxSwitched sw, u32* ptr) {
  SceModuleCB* module_cb;
  int ret = ksceKernelGetModuleCB(this->module_uid, (void**)&module_cb);
  if(ret < 0) {
    return ret;
  }
  switch(this->type) {
  case Type::Offset: {
    *ptr = (u32)module_cb->segments.segments[0].base_addr + this->offset;
    return 0;
  }
  case Type::Import: {
    return module_cb_get_import_func(sw, *module_cb, this->nid.library_nid, this->nid.func_nid, ptr);
  }
  case Type::Export: {
    return module_cb_get_export_func(sw, *module_cb, this->nid.library_nid, this->nid.func_nid, ptr);
  }
  default: {
    return STAI_ERROR_UNEXPECTED;
  }
  }
}

int librarydb_get_module_by_library_nid(SceUID pid, u32 library_nid, SceModuleCB** p_module_cb) {
  SceKernelLibraryDB* libdb = (SceKernelLibraryDB*)ksceKernelGetProcessModuleInfo(pid);
  SceKernelIntrStatus intr = ksceKernelSpinlockLowLockCpuSuspendIntr(&libdb->mutex);
  ksceGUIDReleaseObject(pid);
  SceModuleLibEnt* next = libdb->lib_ents;
  while(next) {
    SceModuleLibEnt* ent = next;
    if(ent->exports->library_nid == library_nid) {
      ksceKernelSpinlockLowUnlockCpuResumeIntr(&libdb->mutex, intr);
      *p_module_cb = ent->module_cb;
      return 0;
    }
    next = ent->next;
  }
  ksceKernelSpinlockLowUnlockCpuResumeIntr(&libdb->mutex, intr);
  return 0x8002d081;
}

static always_inline void write_dacr(u32 dacr) {
  //LOGD("write_dacr: %08x", dacr);
  asm volatile("mcr p15, 0, %0, c3, c0, 0" ::"r"(dacr));
}

static always_inline u32 swap_dacr(u32 new_dacr) {
  u32 old_dacr;
  asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(old_dacr));
  asm volatile("mcr p15, 0, %0, c3, c0, 0" ::"r"(new_dacr));
  //LOGD("swap_dacr: old=%08x new=%08x", old_dacr, new_dacr);
  return old_dacr;
}

void align_cache_line(u32 vma, u32 len, u32& vma_align, u32& len_align) {
  vma_align = vma & ~0x1F;
  len_align = ((vma - vma_align + len + 0x1F) & ~0x1F);
}

void always_inline cache_flush_kernel(u32 vma, size_t len) {
  u32 vma_align, len_align;
  align_cache_line(vma, len, vma_align, len_align);
  LOGD("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);
  ksceKernelL1DcacheCleanInvalidateRange((void*)vma_align, len_align);
  ksceKernelIcacheInvalidateRange((void*)vma_align, len_align);
};

void always_inline cache_flush_user(CtxSwitched, u32 vma, size_t len) {
  u32 vma_align, len_align;
  align_cache_line(vma, len, vma_align, len_align);
  LOGD("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);

  u32 old_dacr = swap_dacr(0x15450FC3);
#if LOG_LEVEL >= 2
  hex_dump((void*)vma_align, len_align);
#endif
  ksceKernelL1DcacheCleanInvalidateRange((void*)vma_align, len_align);
  ksceKernelIcacheInvalidateRange((void*)vma_align, len_align);
  write_dacr(old_dacr);
}

const u32 L2_TYPE_MASK = 0x3;
const u32 L2_TYPE_LARGE = 0x1;
const u32 L2_TYPE_SMALL = 0x2;

const u32 L2_SMALL_ATTR_MASK = 0x00000FFF;
const u32 L2_LARGE_PHYS_MASK = 0xFFFF0000;
const u32 L2_LARGE_ATTR_MASK = 0x0000FFFF;
const u32 L2_LARGE_SLOTS = 16;
const u32 PAGE_SIZE = 0x1000;

SceAddressSpace* get_process_address_space(SceUID pid) {
  SceObjectBase* object;
  int ret = ksceGUIDReferObject(pid, &object);
  if(ret < 0) {
    return nullptr;
  }
  SceUIDProcessObject* process = (SceUIDProcessObject*)object;
  ksceGUIDReleaseObject(pid);
  return process->as;
}

L2PageTable* va_to_l2pagetable(AsCommon& ac, u32 vaddr) {
  u32 entry = ac.l2_pagetable_vector[vaddr >> 0x14];
  if((entry & 3) != 1) {
    return nullptr;
  }
  return reinterpret_cast<L2PageTable*>(entry & ~3);
}

u32 always_inline l2_idx(u32 vaddr) {
  return (vaddr << 0xc) >> 0x18;
}

// Invalidate Unified TLB entry by MVA all ASID Inner Shareable
void TLBIMVAAIS(u32 vaddr) {
  asm volatile("mcr p15, 0, %0, c8, c3, 3" :: "r"(vaddr) : "memory");
}

void split_large_page(u32* pl2pte, u32 base_vaddr) {
  LOGD("base_vaddr=%08x", base_vaddr);
  u32* base_pte = pl2pte + l2_idx(base_vaddr);
  u32 old_pte = *base_pte;
  u32 old_attr = old_pte & L2_LARGE_ATTR_MASK;
  u32 base_paddr = old_pte & L2_LARGE_PHYS_MASK;
  u32 xn = (old_pte >> 15) & 0x1;
  u32 tex = (old_pte >> 12) & 0x7;
  u32 new_attr = (old_attr & L2_SMALL_ATTR_MASK & ~L2_TYPE_MASK) | (tex << 6) | xn | L2_TYPE_SMALL;
  for(u32 i = 0; i < L2_LARGE_SLOTS; i++) {
    u32 new_pte = (base_paddr + (i * PAGE_SIZE)) | new_attr;
    asm volatile("str %0, [%1, %2, lsl#2]" ::"r"(new_pte), "r"(base_pte), "r"(i) : "memory");
  }

  ksceKernelDcacheCleanRange((void*)((u32)base_pte & ~0x1F), 0x20);
  asm volatile("dsb" ::: "memory");
  for(u32 i = 0; i < L2_LARGE_SLOTS; i++) {
    u32 vaddr = base_vaddr + (i * PAGE_SIZE);
    TLBIMVAAIS(vaddr);
  }
  asm volatile("dsb" ::: "memory");
  asm volatile("isb" ::: "memory");
}

int remap_page(SceAddressSpace& as, u32 vaddr, u32 new_paddr) {
  LOGD("vaddr: %08x, new_paddr: %08x", vaddr, new_paddr);

  L2PageTable* l2table = va_to_l2pagetable(*as.ac, vaddr);
  if(!l2table) {
    return STAI_ERROR_REMAP;
  }
  u32* ppte = l2table->pl2pte + l2_idx(vaddr);
  u32 orig = *ppte;

  SceKernelIntrStatus intr = ksceKernelCpuSuspendIntr();
  u32 old_dacr = swap_dacr(0x17450000);
  if((orig & L2_TYPE_MASK) == L2_TYPE_LARGE) {
    split_large_page(l2table->pl2pte, vaddr & ~0xffff);
    orig = *ppte;
  }
  LOGD("orig pte: %08x", orig);

  *ppte = new_paddr | (orig & L2_SMALL_ATTR_MASK);

  ksceKernelDcacheCleanRange((void*)((u32)ppte & ~0x1F), 0x20);
  TLBIMVAAIS(vaddr);
  asm volatile("dsb" ::: "memory");
  asm volatile("isb" ::: "memory");

  write_dacr(old_dacr);
  ksceKernelCpuResumeIntr(intr);
  return 0;
}

void copy_from_to_user_text_domain(void* dst, void* src, size_t len) {
  u32 old_dacr = swap_dacr(0x15450FC3);
  // should usr ldrt and strt but thats not *that* important
  memcpy(dst, src, len); 
  write_dacr(old_dacr);
}

void copy_to_user_text_domain(void* dst, void* src, size_t len) {
  u32 old_dacr = swap_dacr(0x15450FC3);
  // should usr ldrt and strt but thats not *that* important
  memcpy(dst, src, len);
  write_dacr(old_dacr);
}

extern "C" void ksceKernelVAtoPABySW(void*, u32*);

int cow_write(CtxSwitched sw, SceAddressSpace& as, PageRemapVec& remaps, u32 addr, u8* data, u32 len) {
  u32 remaining = len;
  u32 current_vaddr = addr;
  u8* current_data = data;

  while(remaining > 0) {
    u32 page_base = current_vaddr & ~0xfff;
    u32 page_offset = current_vaddr & 0xfff;
    u32 copy_size = (0x1000 - page_offset);
    if(copy_size > remaining) {
      copy_size = remaining;
    }

    auto find = remaps.find(page_base);
    if(!find.is_found()) {
      SceKernelAllocMemBlockKernelOpt opt = {
        .size = sizeof(opt),
        .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID,
        .pid = as.pid,
      };
      SceUID block_uid = ksceKernelAllocMemBlock("stai_cow", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, 0x1000, &opt);
      if(block_uid < 0) {
        return block_uid;
      }
      ksceKernelMapMemBlock(block_uid);
      if(remaps.emplace_at(find, page_base, block_uid) == nullptr) {
        ksceKernelFreeMemBlock(block_uid);
        return STAI_ERROR_OOM;
      }

      void* new_vaddr;
      u32 new_paddr;
      ksceKernelGetMemBlockBase(block_uid, &new_vaddr);
      ksceKernelVAtoPA(new_vaddr, &new_paddr);

      LOGD("copying page to new block: page_base=%08x, new_vaddr=%08x", page_base, new_vaddr);
      copy_from_to_user_text_domain(new_vaddr, (void*)page_base, 0x1000);
      ksceKernelDcacheCleanRange(new_vaddr, 0x1000); // flush the writes to memory

      int ret = remap_page(as, page_base, new_paddr);
      if(ret < 0) {
        return ret;
      }
    }

    LOGD("copying patch: vaddr=%08x, dst=%p, size=%d", page_base, current_vaddr, copy_size);
    copy_to_user_text_domain((void*)current_vaddr, current_data, copy_size);

    current_data += copy_size;
    current_vaddr += copy_size;
    remaining -= copy_size;
  }
  return 0;
}

bool is_shared_address(u32 addr) {
  return addr >= 0xe0000000 && addr <= 0xf0000000;
}

int write_user_text(CtxSwitched sw, SceUID pid, PageRemapVec& remaps, u32 dst, u8* data, u32 len) {
  LOGD("dst=%08x, data=%p, len=%d", dst, data, len);
  LOGD("patch_data:");
  if(DEBUG) {
    hex_dump(data, len);
  }
  
  int ret;
  if(is_shared_address(dst)) {
    SceAddressSpace* as = get_process_address_space(pid);
    if(!as) {
      return STAI_ERROR_REMAP;
    }
    ret = cow_write(sw, *as, remaps, dst, data, len);
  } else {
    copy_to_user_text_domain((void*)dst, data, len);
    u32 dst_align, len_align;
    align_cache_line(dst, len, dst_align, len_align);
    ksceKernelDcacheInvalidateRange((void*)dst_align, len_align);
    ret = 0;
  }
  if(ret < 0) {
    return ret;
  }

  return 0;
}

int PendingWrite::commit(CtxSwitched sw, SceUID pid, PageRemapVec& remaps) {
  return write_user_text(sw, pid, remaps, this->dst, this->data, this->len);
}

struct ExecmemCtx {
  CtxSwitched sw;
  SceUID pid;
  ProcessSlabChain* sch;
  PendingWrite pending_write;
  ExecmemCtx(CtxSwitched sw, SceUID pid, ProcessSlabChain* sch) : sw(sw), pid(pid), sch(sch) {}
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

void hook_module_start(SceModuleCB& module_cb) {
  ScopeLock lock(hook_lock);
  Process* process = Processes::get(module_cb.pid);
  if(!process) {
    return;
  }

  ProcessCtx&& ctx = switch_ctx(module_cb.pid);
  ModuleStartReg* first = nullptr;
  ModuleStartReg* last = nullptr;

  for(size_t i = 0; i < module_cb.lib_export_num; i++) {
    SceModuleExport* exp = &module_cb.exports[i];
    LOGD("exp %s/%s(%08x)", module_cb.module_name, exp->library_name, exp->library_nid);
    auto slice = process->module_start_regs.slice(exp->library_nid);
    for(auto& reg : slice) {
      if(first == nullptr) {
        first = &reg;
      }
      User<StaiRef> next = last ? last->hook_ref : nullptr;
      LOGD("write ref next=%p func=%p old=%p", next, reg.dest_func, module_cb.module_start);
      reg.hook_ref.write(ctx.sw(), StaiRef{
        .next = next,
        .func = reg.dest_func,
        .old = (u32)module_cb.module_start
      });
      last = &reg;
    }
  }

  if(first) {
    module_cb.module_start = (void*)first->dest_func;
  }

  restore_ctx(std::move(ctx));
}

int on_process_exit(SceUID pid, SceProcEventInvokeParam1 *a2, int a3) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Processes::cleanup(pid);
  return 0;
};

int on_process_kill(SceUID pid, SceProcEventInvokeParam1 *a2, int a3) {
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

void after_module_unload(SceModuleCB& module_cb) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Process* process = Processes::get(module_cb.pid);
  if(process) {
    process->cleanup_module(module_cb);
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

static tai_hook_ref_t ModulemgrDestructor_hook_ref;
static SceUID ModulemgrDestructor_hook_id = -1;
static int ModulemgrDestructor_hook(void* data) {
  SceModuleObject* module_obj = (SceModuleObject*)data;
  SceModuleCB& module_cb = module_obj->data;
  if(module_cb.pid != KERNEL_PID) {
    after_module_unload(module_cb);
  }
  return TAI_CONTINUEPP(ModulemgrDestructor_hook, ModulemgrDestructor_hook_ref, data);
}

static tai_hook_ref_t startModuleCommon_hook_ref;
static SceUID startModuleCommon_hook_id = -1;
static int startModuleCommon_hook(SceUID pid, SceUID modid, size_t args, void* argp, void* param_5, void* option, int* status) {
  SceModuleCB* module_cb;
  int ret = ksceKernelGetModuleCB(modid, (void**)&module_cb);
  if(ret < 0) {
    return ret;
  }
  void* real_module_start = module_cb->module_start;
  hook_module_start(*module_cb);
  ret = TAI_CONTINUEPP(startModuleCommon_hook, startModuleCommon_hook_ref, pid, modid, args, argp, param_5, option, status);
  module_cb->module_start = real_module_start;
  return ret;
}

void Process::cleanup_module(SceModuleCB& module_cb) {
  const u32 text_start = (u32)module_cb.segments.segments[0].base_addr;
  const u32 text_end = text_start + module_cb.segments.segments[0].memsz;
  LOGD("module %s text range: %08x-%08x", module_cb.module_name, text_start, text_end);

  auto patch_slice = this->patches.slice(text_start, text_end);
  for(size_t i = 0; i < patch_slice.len; i++) {
    Patch& patch = patch_slice[i];
    if(patch.record) {
      free(patch.record);
      patch.record = nullptr;
    }
  }
  this->patches.erase_slice(std::move(patch_slice));

  auto remap_slice = this->remaps.slice(text_start, text_end);
  for(size_t i = 0; i < remap_slice.len; i++) {
    PageRemap& remap = remap_slice[i];
    if(remap.block_uid) {
      ksceKernelFreeMemBlock(remap.block_uid);
    }
  }
  this->remaps.erase_slice(std::move(remap_slice));
}

int patch_function(CtxSwitched sw, Process* process, Patch* patch, u32 dest_func, User<StaiRef> hook_ref) {
  LOG_FUNC();
  ExecmemCtx ctx(sw, process->pid, &process->sch);

  struct hook_args {
    struct substitute_function_hook hook;
    struct substitute_function_hook_record** record;
    SceUID pid;
    int ret;
  } args{
    .hook = {
      .function = (void*)patch->target_addr,
      .replacement = (void*)dest_func,
      .old_ptr = (void**)&patch->old_func,
      .options = 0,
      .opt = &ctx
    },
    .record = &patch->record,
    .pid = process->pid,
    .ret = -1
  };

  ksceKernelRunWithStack(0x4000, [](void* userarg) {
    hook_args* args = (hook_args*)userarg;
    ProcessCtx&& ctx = switch_ctx(args->pid);
    LOGD("target_addr: %08x", args->hook.function);
    if(DEBUG) {
      hex_dump((void*)((u32)args->hook.function & ~1), 0x20);
    }
    args->ret = substitute_hook_functions(&args->hook, 1, args->record, SUBSTITUTE_RELAXED);
    restore_ctx(std::move(ctx));
    return 0;
  }, &args);
  if(args.ret != SUBSTITUTE_OK) {
    LOGD("substitute_hook_functions failed: %08x (%s)", args.ret, substitute_strerror(args.ret));
    return STAI_ERROR_BASE + args.ret;
  }
  LOGD("old_func: %08x", patch->old_func);

  hook_ref.write(sw, StaiRef{
    .next = nullptr,
    .func = dest_func,
    .old = patch->old_func,
    .target_addr = patch->target_addr,
  });
  if(patch->chain.emplace_back(hook_ref) == nullptr) {
    return STAI_ERROR_MEMORY;
  }

  if(ctx.pending_write.pending()) {
    int ret = ctx.pending_write.commit(sw, process->pid, process->remaps);
    if(ret < 0) {
      return ret;
    }
  }
  return 0;
}

int unpatch_function(CtxSwitched sw, Process* process, Patch* patch) {
  LOG_FUNC();
  if(patch->record == nullptr) {
    return STAI_ERROR_UNEXPECTED;
  }
  auto record = *patch->record;
  free(patch->record);
  patch->record = nullptr;

  u32 dst = (u32)record.function;
  u8* data = (u8*)record.saved_buffer;
  u32 len = record.buffer_size;

  int ret = write_user_text(sw, process->pid, process->remaps, dst, data, len);
  return ret;
}

int Patch::add_hook(CtxSwitched sw, u32 dest_func, User<StaiRef> hook_ref) {
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

int Patch::remove_hook(CtxSwitched sw, Process* process, User<StaiRef> hook_ref) {
  LOG_FUNC();
  size_t index = 0xffffffff;
  size_t chain_len = this->chain.size();
  for(size_t i = 0; i < chain_len; i++) {
    User<StaiRef> ref2 = this->chain[i];
    if(ref2 == hook_ref) {
      index = (int)i;
      break;
    }
  }
  if(index == 0xffffffff) {
    return STAI_ERROR_INVALID_ARGS;
  }

  // is first
  if(index == 0) {
    // and is last
    if(chain_len == 1) {
      int ret = unpatch_function(sw, process, this);
      this->chain.erase(index);
      return ret;
    }

    StaiRef next_ref = this->chain[index + 1].read(sw);
    User<StaiRef> tail = this->chain[this->chain.size() - 1];

    int ret = unpatch_function(sw, process, this);
    if(ret < 0) {
      return ret;
    }
    ret = patch_function(sw, process, this, next_ref.func, tail);
    this->chain.erase(index);
    return ret;
  }

  // is last
  if(index == chain_len - 1) {
    User<StaiRef> prev = this->chain[index - 1];
    StaiRef prev_ref = prev.read(sw);
    prev_ref.next = nullptr;
    prev_ref.old = this->old_func;
    prev.write(sw, prev_ref);
    this->chain.erase(index);
    return 0;
  }

  // in the middle
  auto prev = this->chain[index - 1];
  StaiRef prev_ref = prev.read(sw);
  prev_ref.next = this->chain[index + 1];
  prev.write(sw, prev_ref);
  this->chain.erase(index);
  return 0;
}

int hook_function(CtxSwitched sw, SceUID pid, HookLocation& location, u32 dest_func, User<StaiRef> hook_ref) {
  LOG_FUNC();
  ScopeLock lock(hook_lock);
  Process* process = Processes::get_or_create(pid);
  if(!process) {
    return STAI_ERROR_OOM;
  }

  u32 target_addr;
  int ret = location.resolve(sw, &target_addr);
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
  ret = patch_function(sw, process, patch, dest_func, hook_ref);
  if(ret < 0) {
    process->patches.erase(find);
    return ret;
  }
  return 0;
}

int unhook_function(CtxSwitched sw, SceUID pid, User<StaiRef> hook_ref) {
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
  int ret = patch.remove_hook(sw, process, hook_ref);
  if(ret < 0) {
    return ret;
  }
  if(patch.chain.size() == 0) {
    process->patches.erase(find);
  }
  return 0;
}

int resolve_module_uid(SceUID pid, SceUID module_puid) {
  if(module_puid == 0) {
    return ksceKernelGetModuleIdByPid(pid);
  }
  return kscePUIDtoGUID(pid, module_puid);
}

extern "C" EXPORTED int _staiHookOffset(const _stai_hook_offset_args* uargs) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  auto sw = syscall.sw();
  auto args = read_user(sw, uargs);
  SceUID pid = ksceKernelGetProcessId();

  SceUID module_uid = resolve_module_uid(pid, args.module_uid);
  if(module_uid < 0) {
    LOGD("invalid module_uid: %d", args.module_uid);
    return STAI_ERROR_INVALID_ARGS;
  }
  HookLocation location{
    .module_uid = module_uid,
    .type = HookLocation::Type::Offset,
    .offset = args.offset
  };
  return hook_function(sw, pid, location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiHookExport(const _stai_hook_nid_args* uargs) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  auto sw = syscall.sw();
  auto args = read_user(sw, uargs);
  SceUID pid = ksceKernelGetProcessId();

  SceUID module_uid = resolve_module_uid(pid, args.module_uid);
  if(module_uid < 0) {
    return STAI_ERROR_INVALID_ARGS;
  }
  HookLocation location{
    .module_uid = module_uid,
    .type = HookLocation::Type::Export,
    .nid = {
      .library_nid = args.library_nid,
      .func_nid = args.func_nid,
    },
  };
  return hook_function(sw, pid, location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiHookImport(const _stai_hook_nid_args* uargs) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  auto sw = syscall.sw();
  auto args = read_user(sw, uargs);
  SceUID pid = ksceKernelGetProcessId();

  SceUID module_uid = resolve_module_uid(pid, args.module_uid);
  if(module_uid < 0) {
    return STAI_ERROR_INVALID_ARGS;
  }
  HookLocation location{
    .module_uid = module_uid,
    .type = HookLocation::Type::Import,
    .nid = {
      .library_nid = args.library_nid,
      .func_nid = args.func_nid,
    },
  };
  return hook_function(sw, pid, location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiUnhook(stai_ref_t* hook_ref) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  auto sw = syscall.sw();
  SceUID pid = ksceKernelGetProcessId();
  return unhook_function(sw, pid, User<StaiRef>((StaiRef*)hook_ref));
}

extern "C" EXPORTED int _staiHookModuleStart(const _stai_hook_module_start_args* uargs) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  auto sw = syscall.sw();
  auto args = read_user(sw, uargs);
  SceUID pid = ksceKernelGetProcessId();
  ScopeLock lock(hook_lock);

  User<StaiRef> hook_ref = (StaiRef*)args.ref;

  Process* process = Processes::get_or_create(pid);
  if(!process) {
    LOGD("failed to get or create process for pid %d", pid);
    return STAI_ERROR_OOM;
  }
  if(process->module_start_regs.emplace(args.library_nid, args.dest_func, hook_ref) == nullptr) {
    LOGD("failed to emplace module start reg for library_nid 0x%08x", args.library_nid);
    return STAI_ERROR_OOM;
  }
  return 0;
}

extern "C" EXPORTED int _staiFindModuleByLibraryNid(u32 library_nid, stai_module_info* out_module_info) {
  LOG_FUNC();
  auto syscall = enter_syscall();
  SceUID pid = ksceKernelGetProcessId();

  size_t out_size = 0;
  ksceKernelCopyFromUser(&out_size, out_module_info, sizeof(size_t));
  if(out_size != sizeof(stai_module_info)) {
    return STAI_ERROR_INVALID_ARGS;
  }

  int ret;
  SceModuleCB* module_cb;
  if(library_nid == STAI_MAIN_MODULE) {
    SceUID module_uid = ksceKernelGetModuleIdByPid(pid);
    ret = ksceKernelGetModuleCB(module_uid, (void**)&module_cb);
  } else {
    ret = librarydb_get_module_by_library_nid(pid, library_nid, &module_cb);
  }
  if(ret < 0) {
    return ret;
  }

  if(out_module_info) {
    stai_module_info module_info = {
      .size = sizeof(stai_module_info),
      .module_uid = module_cb->modid_user,
      .fingerprint = module_cb->fingerprint,
      .text_base = (u32)module_cb->segments.segments[0].base_addr,
      .text_size = (u32)module_cb->segments.segments[0].memsz
    };
    ksceKernelCopyToUser(out_module_info, &module_info, sizeof(stai_module_info));
  }
  return 0;
}

int hooks_init(SceUID SceKernelModulemgr_modid) {
  Processes::init();
  hook_lock = ksceKernelCreateMutex("stai_hook_lock", 0, 0, nullptr);

  int ret = ksceKernelRegisterProcEventHandler("stai_proc_event", &proc_event_handler, 0);
  LOGD("ksceKernelRegisterProcEventHandler: %08x", ret);
  if(ret < 0) {
    return ret;
  }

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
  return 0;
}
