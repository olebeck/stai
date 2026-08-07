#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

#include "std.h"
#include "hooks.h"
#include "module.h"
#include "types.h"
#include "stubs.h"
#include "cpu.h"
#include "version.h"

#include "../include/stai/stai.h"


extern "C" int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, void** func);

int get_is_363() {
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

    ret = get_is_363();
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

    ret = hooks_init();
    LOGD("hooks_init: %08x", ret);
    if(ret < 0) {
        return ret;
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
    Syscall syscall;
    auto args = read_user(syscall, uargs);

    SceUID module_uid = resolve_module_uid(syscall.pid(), args.module_uid);
    if(module_uid < 0) {
        LOGD("invalid module_uid: %d", args.module_uid);
        return STAI_ERROR_INVALID_ARGS;
    }
    HookLocation location{
        .module_uid = module_uid,
        .type = HookLocation::Type::Offset,
        .offset = args.offset
    };
    return hook_function(syscall, syscall.pid(), location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiHookExport(const _stai_hook_nid_args* uargs) {
    LOG_FUNC();
    Syscall syscall;
    auto args = read_user(syscall, uargs);

    SceUID module_uid = resolve_module_uid(syscall.pid(), args.module_uid);
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
    return hook_function(syscall, syscall.pid(), location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiHookImport(const _stai_hook_nid_args* uargs) {
    LOG_FUNC();
    Syscall syscall;
    auto args = read_user(syscall, uargs);

    SceUID module_uid = resolve_module_uid(syscall.pid(), args.module_uid);
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
    return hook_function(syscall, syscall.pid(), location, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiUnhook(stai_ref_t* hook_ref) {
    LOG_FUNC();
    Syscall syscall;
    return unhook_function(syscall, syscall.pid(), User((StaiRef*)hook_ref));
}

extern "C" EXPORTED int _staiHookModuleStart(const _stai_hook_module_start_args* uargs) {
    LOG_FUNC();
    Syscall syscall;
    auto args = read_user(syscall, uargs);
    return hook_module_start(syscall.pid(), args.library_nid, args.dest_func, User((StaiRef*)args.ref));
}

extern "C" EXPORTED int _staiFindModuleByLibraryNid(u32 library_nid, stai_module_info* out_module_info) {
    LOG_FUNC();
    Syscall syscall;

    size_t out_size = 0;
    ksceKernelCopyFromUser(&out_size, out_module_info, sizeof(size_t));
    if(out_size != sizeof(stai_module_info)) {
        return STAI_ERROR_INVALID_ARGS;
    }

    int ret;
    SceModuleCB* module_cb;
    if(library_nid == STAI_MAIN_MODULE) {
        ret = ksceKernelGetModuleIdByPid(syscall.pid());
        if(ret > 0) {
            ret = ksceKernelGetModuleCB(ret, (void**)&module_cb);
        }
    } else {
        ret = librarydb_get_module_by_library_nid(syscall.pid(), library_nid, module_cb);
    }
    if(ret < 0) {
        return ret;
    }

    if(out_module_info) {
        User(out_module_info).write(syscall, {
            .size = sizeof(stai_module_info),
            .module_uid = module_cb->modid_user,
            .fingerprint = module_cb->fingerprint,
            .text_base = (u32)module_cb->segments.segments[0].base_addr,
            .text_size = (u32)module_cb->segments.segments[0].memsz
        });
    }
    return 0;
}
