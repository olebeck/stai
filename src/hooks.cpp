#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/proc_event.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen.h>

#include "../include/stai/stai.h"
#include "cow.h"
#include "cpu.h"
#include "hooks.h"
#include "log.h"
#include "module.h"
#include "process.h"
#include "runtime.h"
#include "sync.h"
#include "tai.h"
#include "types.h"

namespace stai::hooks {

static SceUID hook_lock = -1;

void dump_state(SceUID pid);

int HookLocation::resolve(u32& ptr) const {
    ModuleCB* module;
    int ret = ksceKernelGetModuleCB(module_uid, reinterpret_cast<void**>(&module));
    if(ret < 0) {
        return ret;
    }

    SegmentInfo* segment = &module->segments.segments[0];
    switch (type) {
        case Type::Offset: {
            ptr = reinterpret_cast<u32>(segment->base_addr) + offset.offset;
            break;
        }
        case Type::Import: {
            ret = modules::find_import_func(*module, nid.library_nid, nid.func_nid, ptr);
            if(ret == 0) {
                u32 stub[3];
                ksceKernelCopyFromUser(stub, reinterpret_cast<void*>(ptr & ~1), sizeof(stub));
                if(stub[0] == 0xE24FC008 && stub[1] == 0xE12FFF1E) {
                    log::debug("stub for %p has not been resolved yet!", nid.func_nid);
                    return STAI_ERROR_STUB_NOT_RESOLVED;
                }
            }
            break;
        }
        case Type::Export: {
            ret = modules::find_export_func(*module, nid.library_nid, nid.func_nid, ptr);
            break;
        }
        default: {
            ret = STAI_ERROR_INVALID_ARGS;
        }
    }

    u32 start = reinterpret_cast<u32>(segment->base_addr);
    u32 end = start + segment->memsz;
    log::debug("text_start=%08x text_end=%08x dest=%08x", start, end, ptr);
    if(ptr < start || ptr > end) {
        log::error("destination out of bounds");
        return STAI_ERROR_NOT_FOUND;
    }
    return 0;
}

int install(SceUID pid, const HookLocation& location, u32 dest_func, cpu::User<HookRef> hook_ref) {
    log::func(__FUNCTION__);
    ScopeLock lock(hook_lock);
    Process* process = process_registry::get_or_create(pid);
    if(!process) {
        return STAI_ERROR_OOM;
    }

    u32 target_addr = 0;
    int ret = location.resolve(target_addr);
    if(ret < 0) {
        log::debug("failed to resolve hook location: %08x", ret);
        return ret;
    }
    if(target_addr == 0) {
        return STAI_ERROR_NOT_FOUND;
    }

    auto found = process->patches.find(target_addr);
    if(found.is_found()) {
        Patch& patch = process->patches[found.index()];
        return patch.add_hook(dest_func, hook_ref);
    }

    Patch* patch = process->patches.emplace_at(found, target_addr);
    if(!patch) {
        return STAI_ERROR_OOM;
    }
    ret = patch_function(*process, *patch, dest_func, hook_ref);
    if(ret < 0) {
        process->patches.erase(found);
        return ret;
    }
    return 0;
}

int install_module_start(SceUID pid, u32 library_nid, u32 dest_func, cpu::User<HookRef> hook_ref) {
    ScopeLock lock(hook_lock);
    Process* process = process_registry::get_or_create(pid);
    if(!process) {
        return STAI_ERROR_OOM;
    }
    if(process->module_start_regs.emplace(library_nid, dest_func, hook_ref) == nullptr) {
        log::debug("failed to emplace module start reg for library_nid 0x%08x", library_nid);
        return STAI_ERROR_OOM;
    }
    return 0;
}

int uninstall(SceUID pid, cpu::User<HookRef> hook_ref) {
    ScopeLock lock(hook_lock);
    Process* process = process_registry::get_or_create(pid);
    if(!process) {
        return STAI_ERROR_OOM;
    }
    u32 target_addr = hook_ref.read().target_addr;
    if(target_addr == 0) {
        return STAI_ERROR_INVALID_ARGS;
    }
    auto found = process->patches.find(target_addr);
    if(!found.is_found()) {
        return STAI_ERROR_INVALID_ARGS;
    }
    Patch& patch = process->patches[found.index()];
    int ret = patch.remove_hook(*process, hook_ref);
    if(ret < 0) {
        return ret;
    }
    if(patch.chain.size() == 0) {
        process->patches.erase(found);
    }
    return 0;
}

namespace {

void make_module_start_chain(const ModuleCB& module, void*& new_module_start) {
    ScopeLock lock(hook_lock);
    Process* process = process_registry::get(module.pid);
    if(!process) {
        return;
    }

    SceKernelProcessContext* context = cpu::get_process_context(module.pid);
    if(!context) {
        return;
    }
    cpu::SwitchCtx switch_ctx(context);

    ModuleStartReg* first = nullptr;
    ModuleStartReg* previous = nullptr;
    for(size_t i = 0; i < module.lib_export_num; i++) {
        ModuleExports* exports = &module.exports[i];
        for(auto& reg : process->module_start_regs.slice(exports->lib_nid)) {
            log::debug("write ref func=%p old=%p", reg.dest_func, module.module_start);
            reg.hook_ref.write(HookRef{
                .next = cpu::User<HookRef>(),
                .func = reg.dest_func,
                .old = reinterpret_cast<u32>(module.module_start),
            });
            if(first == nullptr) {
                first = &reg;
            }
            if(previous) {
                HookRef previous_ref = previous->hook_ref.read();
                previous_ref.next = reg.hook_ref;
                previous_ref.old = 0;
                previous->hook_ref.write(previous_ref);
            }
            previous = &reg;
        }
    }
    if(first) {
        new_module_start = reinterpret_cast<void*>(first->dest_func);
    }
}

int on_process_exit(SceUID pid, SceProcEventInvokeParam1* a2, int a3) {
    (void)a2;
    (void)a3;
    log::func(__FUNCTION__);
    ScopeLock lock(hook_lock);
    process_registry::cleanup(pid);
    return 0;
}

int on_process_kill(SceUID pid, SceProcEventInvokeParam1* a2, int a3) {
    (void)a2;
    (void)a3;
    log::func(__FUNCTION__);
    ScopeLock lock(hook_lock);
    process_registry::cleanup(pid);
    return 0;
}

SceProcEventHandler proc_event_handler = {
    .size = sizeof(SceProcEventHandler),
    .exit = on_process_exit,
    .kill = on_process_kill,
};

} // namespace

TAI_HOOK(int, ModulemgrDestructor, void* data) {
    auto* module_obj = static_cast<ModuleObject*>(data);
    const ModuleCB& module = module_obj->data;
    if(module.pid != KERNEL_PID) {
        ScopeLock lock(hook_lock);
        Process* process = process_registry::get(module.pid);
        if(process) {
            dump_state(module.pid);
            process->cleanup_module(module, true);
        } else {
            release_module_cow(module, true);
        }
    }
    return TAI_HOOK_CONTINUE(ModulemgrDestructor, data);
}

TAI_HOOK(int, startModuleCommon, SceUID pid, SceUID modid, size_t argc, void* argv, void* param_5, void* option, int* status) {
    if(pid == KERNEL_PID) {
        return TAI_HOOK_CONTINUE(startModuleCommon, pid, modid, argc, argv, param_5, option, status);
    }

    ModuleCB* module;
    int ret = ksceKernelGetModuleCB(modid, reinterpret_cast<void**>(&module));
    if(ret < 0) {
        return ret;
    }
    void* new_module_start = nullptr;
    make_module_start_chain(*module, new_module_start);

    void* real_module_start = module->module_start;
    if(new_module_start) {
        module->module_start = new_module_start;
    }
    ret = TAI_HOOK_CONTINUE(startModuleCommon, pid, modid, argc, argv, param_5, option, status);
    module->module_start = real_module_start;
    dump_state(module->pid);
    return ret;
}

TAI_HOOK(int, ModulemgrStopModule, SceUID pid, SceUID modid, int argc, void* argv, void* param_5, void* option, int* status) {
    if(pid != KERNEL_PID) {
        ScopeLock lock(hook_lock);
        ModuleCB* module;
        int ret = ksceKernelGetModuleCB(modid, reinterpret_cast<void**>(&module));
        if(ret < 0) {
            return ret;
        }
        Process* process = process_registry::get(pid);
        if(process) {
            dump_state(module->pid);
            process->cleanup_module(*module, false);
        } else {
            release_module_cow(*module, false);
        }
    }
    return TAI_HOOK_CONTINUE(ModulemgrStopModule, pid, modid, argc, argv, param_5, option, status);
}

int init() {
    process_registry::init();

    hook_lock = ksceKernelCreateMutex("stai_hook_lock", 0, 0, nullptr);

    int ret = ksceKernelRegisterProcEventHandler("stai_proc_event", &proc_event_handler, 0);
    log::debug("ksceKernelRegisterProcEventHandler: %08x", ret);
    if(ret < 0) {
        return ret;
    }

    ret = ksceKernelSearchModuleByName("SceKernelModulemgr");
    log::debug("ksceKernelSearchModuleByName(SceKernelModulemgr): %08x", ret);
    if(ret < 0) {
        return ret;
    }
    SceUID modulemgr_modid = ret;

    SceClass* module_class;
    ret = ksceKernelFindClassByName("SceUIDModuleClass", &module_class);
    log::debug("ksceKernelFindClassByName: %08x", ret);
    if(ret < 0) {
        return ret;
    }

    ret = taiHookFunctionAbs(
        KERNEL_PID,
        &ModulemgrDestructor_hook_ref,
        reinterpret_cast<void*>(module_class->destroy_cb),
        reinterpret_cast<void*>(ModulemgrDestructor_hook));
    log::debug("taiHookFunctionAbs(ModulemgrDestructor): %08x", ret);
    if(ret < 0) {
        return ret;
    }
    ModulemgrDestructor_hook_id = ret;

    TAI_HOOK_OFFSET(modulemgr_modid, startModuleCommon, 0x286C);
    TAI_HOOK_OFFSET(modulemgr_modid, ModulemgrStopModule, 0x2b40);

    return 0;
}

#ifdef STAI_DEBUG
void dump_state(SceUID pid) {
    Process* process = process_registry::get(pid);
    if(!process) {
        log::debug("no state pid=%08x", pid);
        return;
    }

    log::debug("pid=%08x", pid);
    log::debug("process->patches.size: %d", process->patches.size());
    for(auto& patch : process->patches) {
        log::debug("  target_addr=%08x record=%08x old_func=%08x", patch.target_addr, patch.record, patch.old_func);
        log::debug("  chain.size: %d", patch.chain.size());
        for(auto& entry : patch.chain) {
            log::debug("    chain ptr: %08x", entry.raw());
        }
    }
    log::debug("");

    cow::dump_state(pid);

    log::debug("process->module_start_regs.size: %d", process->module_start_regs.size());
    for(auto& reg : process->module_start_regs) {
        log::debug("  library_nid=%08x dest_func=%08x hook_ref=%08x", reg.library_nid, reg.dest_func, reg.hook_ref.raw());
    }
    log::debug("");
}
#else
void dump_state(SceUID pid) {
    (void)pid;
}
#endif

} // namespace stai::hooks
