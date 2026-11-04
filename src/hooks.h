#pragma once

#include <psp2kern/types.h>
#include "std++.h"
#include "cpu.h"

struct StaiRef {
    User<StaiRef> next;
    u32 func;
    u32 old;
    u32 target_addr;
    StaiRef() = default;
};

struct HookLocation {
    enum class Type {
        Offset,
        Import,
        Export
    };

    SceUID module_uid;
    Type type;
    union {
        struct {
            u32 offset;
        } offset;
        struct {
            u32 library_nid;
            u32 func_nid;
        } nid;
    };

    int resolve(CtxSwitched& sw, u32& out_ptr) const;
};

int hooks_init();

int hook_function(CtxSwitched& sw, SceUID pid, const HookLocation& location, u32 dest_func, User<StaiRef> hook_ref);

int hook_module_start(SceUID pid, u32 library_nid, u32 dest_func, User<StaiRef> hook_ref);

int unhook_function(CtxSwitched& sw, SceUID pid, User<StaiRef> hook_ref);

int write_process_text(CtxSwitched& sw, SceUID pid, u32 dst, const u8* data, u32 len);
