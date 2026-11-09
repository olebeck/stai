#include "process.h"

#include <psp2kern/kernel/threadmgr.h>
#include <string.h>

#include "../include/stai/stai.h"
#include "cow.h"
#include "log.h"
#include "runtime.h"

extern "C" {
#include "../substitute/lib/execmem.h"
#include "../substitute/lib/substitute.h"
}

namespace stai::hooks {

Process::~Process() {
    pid = 0;
    for(auto& patch : patches) {
        if(patch.record) {
            free(patch.record);
            patch.record = nullptr;
        }
    }
}

struct ExecmemCtx {
    SceUID pid;
    ProcessSlabChain* slab_chain;
    PendingWrite pending_write;

    ExecmemCtx(SceUID pid, ProcessSlabChain* slab_chain)
        : pid(pid), slab_chain(slab_chain) {}
};

namespace {

int install_function_patch(Process& process, Patch& patch, u32 dest_func) {
    log::func(__FUNCTION__);
    ExecmemCtx ctx(process.pid, &process.slab_chain);

    struct hook_args {
        struct substitute_function_hook hook;
        struct substitute_function_hook_record** record;
        SceUID pid;
        int ret;
    } args{
        .hook = {
            .function = reinterpret_cast<void*>(patch.target_addr),
            .replacement = reinterpret_cast<void*>(dest_func),
            .old_ptr = reinterpret_cast<void**>(&patch.old_func),
            .options = 0,
            .opt = &ctx,
        },
        .record = &patch.record,
        .pid = process.pid,
        .ret = -1,
    };

    ksceKernelRunWithStack(0x4000, [](void* userarg) {
        auto* hook_args_ptr = static_cast<hook_args*>(userarg);
        SceKernelProcessContext* context = cpu::get_process_context(hook_args_ptr->pid);
        if(!context) {
            hook_args_ptr->ret = STAI_ERROR_INVALID_ARGS;
            return 0;
        }
        cpu::SwitchCtx switch_ctx(context);
#ifdef STAI_DEBUG
        log::debug("target_addr: %08x", hook_args_ptr->hook.function);
        hex_dump(reinterpret_cast<void*>(reinterpret_cast<u32>(hook_args_ptr->hook.function) & ~1), 0x20);
#endif
        hook_args_ptr->ret = substitute_hook_functions(&hook_args_ptr->hook, 1, hook_args_ptr->record, SUBSTITUTE_RELAXED);
        return 0;
    }, &args);

    if(args.ret != SUBSTITUTE_OK) {
        log::debug("substitute_hook_functions failed: %08x (%s)", args.ret, substitute_strerror(args.ret));
        return STAI_ERROR_BASE + args.ret;
    }

    if(ctx.pending_write.pending()) {
        SceUID cow_uid = -1;
        int ret = ctx.pending_write.commit(process.pid, cow_uid);
        if(ret < 0) {
            free(patch.record);
            patch.record = nullptr;
            return ret;
        }
        patch.cow_uid = cow_uid;
    }
    return 0;
}

int unpatch_function(Process& process, Patch& patch) {
    (void)process;
    log::func(__FUNCTION__);
    if(patch.record == nullptr) {
        return STAI_ERROR_UNEXPECTED;
    }
    int ret = 0;
    if(patch.cow_uid >= 0) {
        ret = cow::release(patch.cow_uid);
        patch.cow_uid = -1;
    }
    free(patch.record);
    patch.record = nullptr;
    return ret;
}

int repatch_function(Process& process, Patch& patch, u32 new_dest, cpu::User<HookRef> tail) {
    int ret = unpatch_function(process, patch);
    if(ret < 0) {
        return ret;
    }
    ret = install_function_patch(process, patch, new_dest);
    if(ret < 0) {
        return ret;
    }

    HookRef tail_ref = tail.read();
    tail_ref.old = patch.old_func;
    tail.write(tail_ref);
    return 0;
}

} // namespace

int PendingWrite::commit(SceUID pid, SceUID& out_uid) {
    out_uid = cow::write(pid, dst, data, len);
    return out_uid < 0 ? out_uid : 0;
}

int patch_function(Process& process, Patch& patch, u32 dest_func, cpu::User<HookRef> hook_ref) {
    log::func(__FUNCTION__);
    int ret = install_function_patch(process, patch, dest_func);
    if(ret < 0) {
        return ret;
    }

    hook_ref.write(HookRef{
        .next = cpu::User<HookRef>(),
        .func = dest_func,
        .old = patch.old_func,
        .target_addr = patch.target_addr,
    });
    if(patch.chain.emplace_back(hook_ref) == nullptr) {
        return STAI_ERROR_MEMORY;
    }
    return 0;
}

void release_module_cow(const ModuleCB& module, bool destructing) {
    const u32 text_start = reinterpret_cast<u32>(module.segments.segments[0].base_addr);
    const u32 text_end = text_start + module.segments.segments[0].memsz;

    SceKernelProcessContext* context = cpu::get_process_context(module.pid);
    if(!destructing && context != nullptr) {
        cpu::SwitchCtx switch_ctx(context);
        int ret = cow::release_range(module.pid, text_start, text_end, true);
        log::debug("cow::release_range: %08x", ret);
    } else {
        int ret = cow::release_range(module.pid, text_start, text_end, false);
        log::debug("cow::release_range: %08x", ret);
    }
}

void Process::cleanup_module(const ModuleCB& module, bool destructing) {
    const u32 text_start = reinterpret_cast<u32>(module.segments.segments[0].base_addr);
    const u32 text_end = text_start + module.segments.segments[0].memsz;

    SceKernelProcessContext* context = cpu::get_process_context(module.pid);
    bool can_write = !destructing && context != nullptr;
    if(can_write) {
        cpu::SwitchCtx switch_ctx(context);

        auto patch_slice = patches.slice(text_start, text_end);
        if(patch_slice.len) {
            log::debug("module %s text range: %08x-%08x patches=%d", module.module_name, text_start, text_end, patch_slice.len);
            for(Patch& patch : patch_slice) {
                if(patch.record) {
                    int ret = unpatch_function(*this, patch);
                    log::debug("unpatch_function: %08x", ret);
                }
            }
            patches.erase_slice(patch_slice);
        }
    } else {
        auto patch_slice = patches.slice(text_start, text_end);
        if(patch_slice.len) {
            log::debug("module %s text range: %08x-%08x patches=%d", module.module_name, text_start, text_end, patch_slice.len);
            for(Patch& patch : patch_slice) {
                if(patch.record) {
                    free(patch.record);
                    patch.record = nullptr;
                }
            }
            patches.erase_slice(patch_slice);
        }
    }
    release_module_cow(module, destructing);
}

int Patch::add_hook(u32 dest_func, cpu::User<HookRef> hook_ref) {
    log::func(__FUNCTION__);
    for(auto& existing_ref : chain) {
        if(existing_ref == hook_ref) {
            return STAI_ERROR_INVALID_ARGS;
        }
    }

    hook_ref.write(HookRef{
        .next = cpu::User<HookRef>(),
        .func = dest_func,
        .old = old_func,
        .target_addr = target_addr,
    });
    if(chain.emplace_back(hook_ref) == nullptr) {
        return STAI_ERROR_OOM;
    }

    cpu::User<HookRef> previous = chain[chain.size() - 2];
    HookRef previous_ref = previous.read();
    previous_ref.next = hook_ref;
    previous_ref.old = 0;
    previous.write(previous_ref);
    return 0;
}

int Patch::find_ref(cpu::User<HookRef> target) const {
    size_t chain_len = chain.size();
    for(size_t i = 0; i < chain_len; i++) {
        cpu::User<HookRef> existing_ref = chain[i];
        if(existing_ref == target) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int Patch::remove_first(Process& process) {
    if(chain.size() < 2) {
        return STAI_ERROR_UNEXPECTED;
    }
    HookRef next_ref = chain[1].read();
    cpu::User<HookRef> tail = *chain.back();

    int ret = repatch_function(process, *this, next_ref.func, tail);
    if(ret < 0) {
        return ret;
    }
    chain.erase(0);
    return 0;
}

void Patch::remove_middle(int index) {
    auto previous = chain[index - 1];
    HookRef previous_ref = previous.read();
    previous_ref.next = chain[index + 1];
    previous.write(previous_ref);
    chain.erase(index);
}

void Patch::remove_last(int index) {
    cpu::User<HookRef> previous = chain[index - 1];
    HookRef previous_ref = previous.read();
    previous_ref.next = cpu::User<HookRef>();
    previous_ref.old = old_func;
    previous.write(previous_ref);
    chain.erase(index);
}

int Patch::remove_hook(Process& process, cpu::User<HookRef> hook_ref) {
    log::func(__FUNCTION__);
    int index = find_ref(hook_ref);
    if(index < 0) {
        return STAI_ERROR_INVALID_ARGS;
    }

    if(index == 0) {
        if(chain.size() == 1) {
            int ret = unpatch_function(process, *this);
            chain.erase(index);
            return ret;
        }
        return remove_first(process);
    }

    if(static_cast<size_t>(index) == chain.size() - 1) {
        remove_last(index);
        return 0;
    }

    remove_middle(index);
    return 0;
}

namespace process_registry {

static int slot = -1;

int init() {
    slot = ksceKernelCreateProcessLocalStorage("stai_process", sizeof(Process));
    log::debug("ksceKernelCreateProcessLocalStorage: %d", slot);
    return slot;
}

Process* get(SceUID pid) {
    Process* process = nullptr;
    ksceKernelGetProcessLocalStorageAddrForPid(pid, slot, reinterpret_cast<void**>(&process), 0);
    if(process == nullptr || process->pid == 0) {
        return nullptr;
    }
    return process;
}

Process* get_or_create(SceUID pid) {
    Process* process = nullptr;
    ksceKernelGetProcessLocalStorageAddrForPid(pid, slot, reinterpret_cast<void**>(&process), 1);
    if(process && process->pid == 0) {
        process = new (process) Process(pid);
    }
    return process;
}

void cleanup(SceUID pid) {
    Process* process = get(pid);
    if(process && process->pid != 0) {
        process->~Process();
    }
    cow::cleanup(pid);
}

} // namespace process_registry

} // namespace stai::hooks

extern "C" int execmem_alloc_unsealed(uintptr_t hint, void** ptr, uintptr_t* vma, size_t* size, void* opt) {
    (void)hint;
    auto* ctx = static_cast<stai::hooks::ExecmemCtx*>(opt);
    *ptr = ctx->slab_chain->alloc(ctx->pid, vma);
    if(*ptr) {
        *size = stai::hooks::kPatchItemSize;
        return SUBSTITUTE_OK;
    }
    return STAI_ERROR_OOM;
}

extern "C" int execmem_seal(void* ptr, void* opt) {
    auto* ctx = static_cast<stai::hooks::ExecmemCtx*>(opt);
    u32 vma = ctx->slab_chain->getmirror(ptr);
    stai::cpu::cache_flush_kernel(reinterpret_cast<u32>(ptr), stai::hooks::kPatchItemSize);
    stai::cpu::cache_flush_user(vma, stai::hooks::kPatchItemSize);
    return SUBSTITUTE_OK;
}

extern "C" void execmem_free(void* ptr, void* opt) {
    auto* ctx = static_cast<stai::hooks::ExecmemCtx*>(opt);
    ctx->slab_chain->free(ptr);
}

extern "C" int execmem_foreign_write_with_pc_patch(struct execmem_foreign_write* writes, size_t nwrites, execmem_pc_patch_callback callback, void* callback_ctx) {
    (void)callback;
    (void)callback_ctx;
    if(nwrites < 1) {
        return SUBSTITUTE_OK;
    }
    execmem_foreign_write* write = &writes[0];
    stai::log::debug("dst=%08x, src=%p, len=%d", write->dst, write->src, write->len);

    auto* ctx = static_cast<stai::hooks::ExecmemCtx*>(write->opt);
    ctx->pending_write.dst = reinterpret_cast<u32>(write->dst);
    ctx->pending_write.len = write->len;
    STAI_DEBUG_ASSERT(write->len < sizeof(ctx->pending_write.data));
    memcpy(ctx->pending_write.data, write->src, write->len);
    return SUBSTITUTE_OK;
}
