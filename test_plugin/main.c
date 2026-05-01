#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/sysmodule.h>
#include "../include/stai/stai.h"

void* memset(void* dst, int ch, size_t len) {
    return sceClibMemset(dst, ch, len);
}

const uint32_t SceHttp_library_nid = 0xE8F15CDE;

typedef struct http_template_t {
    uint8_t padding[0xb0];
    void* (*alloc)(size_t size);
    void (*free)(void* ptr);
} http_template_t;

STAI_HOOK(int, templateCreateConnection, http_template_t* template, const char* serverName, const char* scheme, const char* username, const char* password, uint16_t port, SceBool enableKeepalive, int param_8, void* param_9) {
    sceClibPrintf("templateCreateConnection %s\n", serverName);
    return STAI_HOOK_CONTINUE(templateCreateConnection, template, serverName, scheme, username, password, port, enableKeepalive, param_8, param_9);
}

STAI_HOOK(int, SceHttp_module_start, SceSize argc, void* argv) {
    sceClibPrintf("SceHttp module start!!\n");

    sceClibPrintf("ref: %p\n", &SceHttp_module_start_hook_ref);
    sceClibPrintf("self: %p\n", SceHttp_module_start_hook);
    sceClibPrintf("next: %p\n", SceHttp_module_start_hook_ref.next);
    sceClibPrintf("func: %p\n", SceHttp_module_start_hook_ref.func);
    sceClibPrintf("old: %p\n", SceHttp_module_start_hook_ref.old);

    stai_module_info SceHttp_module_info = { .size = sizeof(stai_module_info) };
    int ret = staiFindModuleByLibraryNid(SceHttp_library_nid, &SceHttp_module_info);
    sceClibPrintf("staiFindModuleByLibraryNid: %08x\n", ret);
    if(ret == 0) {
        int ret = staiHookOffset(
            SceHttp_module_info.module_uid,
            0x2434, 1,
            templateCreateConnection_hook,
            &templateCreateConnection_hook_ref
        );
        sceClibPrintf("staiHookOffset: %08x\n", ret);
    }

    return STAI_HOOK_CONTINUE(SceHttp_module_start, argc, argv);
}

int module_start(size_t argc, void* argv) {
    int ret = staiHookModuleStart(SceHttp_library_nid, SceHttp_module_start_hook, &SceHttp_module_start_hook_ref);
    sceClibPrintf("staiHookModuleStart: %08x\n", ret);
    return 0;
}

int module_stop(SceSize argc, const void* argv) {
    return 0;
}
