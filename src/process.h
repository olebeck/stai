#pragma once

#include "cow.h"
#include "cpu.h"
#include "hooks.h"
#include "slab.h"
#include "sorted_vec.h"
#include "types.h"
#include "vec.h"

struct substitute_function_hook_record;

namespace stai::hooks {

constexpr size_t kPatchItemSize = 0x100;

class Process;

struct Patch {
    u32 target_addr;
    substitute_function_hook_record* record;
    u32 old_func;
    Vec<cpu::User<HookRef>> chain;

    explicit Patch(u32 target_addr)
        : target_addr(target_addr), record(nullptr), old_func(0) {};

    Patch(const Patch&) = delete;
    Patch& operator=(const Patch&) = delete;
    Patch(Patch&&) = default;
    Patch& operator=(Patch&&) = default;

    int add_hook(u32 dest_func, cpu::User<HookRef> hook_ref);
    int remove_hook(Process& process, cpu::User<HookRef> hook_ref);
    int find_ref(cpu::User<HookRef> target) const;

private:
    int remove_first(Process& process);
    void remove_last(int index);
    void remove_middle(int index);
};

using PatchVec = SortedVec<Patch, u32, &Patch::target_addr>;

struct PendingWrite {
    u32 dst = 0;
    u32 len = 0;
    u8 data[kPatchItemSize];

    PendingWrite() = default;

    bool pending() const { return dst != 0; }
    int commit(SceUID pid, cow::PageRemapVec& remaps);
};

struct ModuleStartReg {
    u32 library_nid;
    u32 dest_func;
    cpu::User<HookRef> hook_ref;

    ModuleStartReg(u32 library_nid, u32 dest_func, cpu::User<HookRef> hook_ref)
        : library_nid(library_nid), dest_func(dest_func), hook_ref(hook_ref) {};

    ModuleStartReg(const ModuleStartReg&) = default;
    ModuleStartReg& operator=(const ModuleStartReg&) = default;
    ModuleStartReg(ModuleStartReg&&) = default;
    ModuleStartReg& operator=(ModuleStartReg&&) = default;
};

using ModuleStartRegVec = SortedDupVec<ModuleStartReg, u32, &ModuleStartReg::library_nid>;
using ProcessSlabChain = SlabChain<kPatchItemSize>;

class Process {
public:
    SceUID pid;
    ProcessSlabChain slab_chain;
    PatchVec patches;
    cow::PageRemapVec remaps;
    ModuleStartRegVec module_start_regs;

    explicit Process(SceUID pid)
         : pid(pid) {};

    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&&) = default;
    Process& operator=(Process&&) = default;

    ~Process();

    void cleanup_module(const ModuleCB& module, bool destructing);
};

namespace process_registry {

int init();
Process* get(SceUID pid);
Process* get_or_create(SceUID pid);
void cleanup(SceUID pid);

} // namespace process_registry

int patch_function(Process& process, Patch& patch, u32 dest_func, cpu::User<HookRef> hook_ref);

} // namespace stai::hooks
