#pragma once

#include <psp2kern/types.h>

#include "cpu.h"

namespace stai::hooks {

struct HookRef {
    cpu::User<HookRef> next;
    u32 func;
    u32 old;
    u32 target_addr;

    HookRef() = default;
};

struct HookLocation {
    enum class Type {
        Offset,
        Import,
        Export,
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

    int resolve(u32& out_ptr) const;
};

int init();

int install(SceUID pid, const HookLocation& location, u32 dest_func, cpu::User<HookRef> hook_ref);

int install_module_start(SceUID pid, u32 library_nid, u32 dest_func, cpu::User<HookRef> hook_ref);

int uninstall(SceUID pid, cpu::User<HookRef> hook_ref);

} // namespace stai::hooks
