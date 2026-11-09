#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

#include "../include/stai/stai.h"
#include "../include/stai/stai_kernel.h"
#include "cow.h"
#include "cpu.h"
#include "hooks.h"
#include "log.h"
#include "module.h"
#include "runtime.h"
#include "types.h"
#include "version.h"

using namespace stai;

namespace {

int resolve_module_uid(SceUID pid, SceUID module_puid) {
    if(module_puid == 0) {
        return ksceKernelGetModuleIdByPid(pid);
    }
    return kscePUIDtoGUID(pid, module_puid);
}

} // namespace

extern "C" void stai_stubs_init();

extern "C" STAI_EXPORTED int module_start(SceSize argc, const void* argv) {
    (void)argc;
    (void)argv;

    log::info(GIT_COMMIT " starting");
#ifdef STAI_VERSION
    log::info("version: " STAI_VERSION);
#endif

    stai_stubs_init();

    int ret = heap_init();
    if(ret < 0) {
        log::error("heap_init: %08x", ret);
        return SCE_KERNEL_START_FAILED;
    }

    ret = cow::init();
    if(ret < 0) {
        log::error("cow::init: %08x", ret);
        return SCE_KERNEL_START_FAILED;
    }

    ret = hooks::init();
    if(ret < 0) {
        log::error("hooks_init: %08x", ret);
        return SCE_KERNEL_START_FAILED;
    }
    return 0;
}

extern "C" STAI_EXPORTED int _staiHookOffset(const _stai_hook_offset_args* uargs) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    auto args = cpu::read_user(uargs);
    SceUID pid = ksceKernelGetProcessId();

    SceUID module_uid = resolve_module_uid(pid, args.module_uid);
    if(module_uid < 0) {
        log::debug("invalid module_uid: %d", args.module_uid);
        return STAI_ERROR_INVALID_ARGS;
    }
    hooks::HookLocation location{
        .module_uid = module_uid,
        .type = hooks::HookLocation::Type::Offset,
        .offset = args.offset,
    };
    return hooks::install(pid, location, args.dest_func, cpu::User(reinterpret_cast<hooks::HookRef*>(args.ref)));
}

extern "C" STAI_EXPORTED int _staiHookExport(const _stai_hook_nid_args* uargs) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    auto args = cpu::read_user(uargs);
    SceUID pid = ksceKernelGetProcessId();

    SceUID module_uid = resolve_module_uid(pid, args.module_uid);
    if(module_uid < 0) {
        return STAI_ERROR_INVALID_ARGS;
    }
    hooks::HookLocation location{
        .module_uid = module_uid,
        .type = hooks::HookLocation::Type::Export,
        .nid = {
            .library_nid = args.library_nid,
            .func_nid = args.func_nid,
        },
    };
    return hooks::install(pid, location, args.dest_func, cpu::User(reinterpret_cast<hooks::HookRef*>(args.ref)));
}

extern "C" STAI_EXPORTED int _staiHookImport(const _stai_hook_nid_args* uargs) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    auto args = cpu::read_user(uargs);
    SceUID pid = ksceKernelGetProcessId();

    SceUID module_uid = resolve_module_uid(pid, args.module_uid);
    if(module_uid < 0) {
        return STAI_ERROR_INVALID_ARGS;
    }
    hooks::HookLocation location{
        .module_uid = module_uid,
        .type = hooks::HookLocation::Type::Import,
        .nid = {
            .library_nid = args.library_nid,
            .func_nid = args.func_nid,
        },
    };
    return hooks::install(pid, location, args.dest_func, cpu::User(reinterpret_cast<hooks::HookRef*>(args.ref)));
}

extern "C" STAI_EXPORTED int _staiUnhook(stai_ref_t* hook_ref) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    SceUID pid = ksceKernelGetProcessId();
    return hooks::uninstall(pid, cpu::User(reinterpret_cast<hooks::HookRef*>(hook_ref)));
}

extern "C" STAI_EXPORTED int _staiHookModuleStart(const _stai_hook_module_start_args* uargs) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    auto args = cpu::read_user(uargs);
    SceUID pid = ksceKernelGetProcessId();
    return hooks::install_module_start(pid, args.library_nid, args.dest_func, cpu::User(reinterpret_cast<hooks::HookRef*>(args.ref)));
}

extern "C" STAI_EXPORTED int _staiFindModuleByLibraryNid(u32 library_nid, stai_module_info* out_module_info) {
    log::func(__FUNCTION__);
    cpu::Syscall syscall;
    SceUID pid = ksceKernelGetProcessId();

    size_t out_size = 0;
    ksceKernelCopyFromUser(&out_size, out_module_info, sizeof(size_t));
    if(out_size != sizeof(stai_module_info)) {
        return STAI_ERROR_INVALID_ARGS;
    }

    int ret;
    ModuleCB* module;
    if(library_nid == STAI_MAIN_MODULE) {
        ret = ksceKernelGetModuleIdByPid(pid);
        if(ret > 0) {
            ret = ksceKernelGetModuleCB(ret, reinterpret_cast<void**>(&module));
        }
    } else {
        ret = modules::find_module_by_library_nid(pid, library_nid, module);
    }
    if(ret < 0) {
        return ret;
    }

    if(out_module_info) {
        cpu::User(out_module_info).write({
            .size = sizeof(stai_module_info),
            .module_uid = module->modid_user,
            .fingerprint = module->fingerprint,
            .text_base = reinterpret_cast<u32>(module->segments.segments[0].base_addr),
            .text_size = reinterpret_cast<u32>(module->segments.segments[0].memsz),
        });
    }
    return 0;
}

extern "C" STAI_EXPORTED SceUID staiCowWrite(SceUID pid, uint32_t addr, const void* data, uint32_t size) {
    log::func(__FUNCTION__);
    if(size == 0 || data == nullptr) {
        return STAI_ERROR_INVALID_ARGS;
    }

    SceKernelProcessContext* context = cpu::get_process_context(pid);
    if(!context) {
        return STAI_ERROR_INVALID_ARGS;
    }
    cpu::SwitchCtx switch_ctx(context);
    return cow::write(pid, addr, static_cast<const u8*>(data), size);
}

extern "C" STAI_EXPORTED int staiCowRelease(SceUID uid) {
    log::func(__FUNCTION__);
    return cow::release(uid);
}
