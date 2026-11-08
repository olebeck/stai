#include "module.h"

#include "log.h"

namespace stai::modules {

namespace {

constexpr int kErrorNotFound = 0x8002d081;
constexpr u32 kAnyLibraryNid = 0xffffffff;

int find_nid_user(u32* nids, void** entries, u32 count, u32 nid, u32& out_entry) {
    cpu::Dacr dacr(0x55555555);
    for (u32 i = 0; i < count; i++) {
        u32 entry_nid;
        asm ("ldrt %0, [%1]" : "=r"(entry_nid) : "r"(nids + i));
        if(entry_nid == nid) {
            asm ("ldrt %0, [%1]" : "=r"(out_entry) : "r"(entries + i));
            return 0;
        }
    }
    return -1;
}

} // namespace

int find_module_by_library_nid(SceUID pid, u32 library_nid, ModuleCB*& out_module) {
    auto* library_db = reinterpret_cast<LibraryDB*>(ksceKernelGetProcessModuleInfo(pid));
    SceKernelIntrStatus intr = ksceKernelSpinlockLowLockCpuSuspendIntr(&library_db->mutex);
    ksceGUIDReleaseObject(pid);

    ModuleLibEnt* entry = library_db->lib_ents;
    while (entry) {
        if(entry->exports->lib_nid == library_nid) {
            ksceKernelSpinlockLowUnlockCpuResumeIntr(&library_db->mutex, intr);
            out_module = entry->module_cb;
            return 0;
        }
        entry = entry->next;
    }

    ksceKernelSpinlockLowUnlockCpuResumeIntr(&library_db->mutex, intr);
    return kErrorNotFound;
}

int find_export_func(const ModuleCB& module, u32 library_nid, u32 func_nid, u32& out_func) {
    u32 current = module.libent_top;
    while (current < module.libent_btm) {
        ModuleExports exports = cpu::copy_from_user(reinterpret_cast<ModuleExports*>(current));
        if(library_nid == kAnyLibraryNid || exports.lib_nid == library_nid) {
            if(find_nid_user(exports.nid_table, exports.entry_table, exports.num_functions, func_nid, out_func) == 0) {
                return 0;
            }
        }
        current += exports.size;
    }
    return kErrorNotFound;
}

int find_import_func(const ModuleCB& module, u32 library_nid, u32 func_nid, u32& out_func) {
    u32 current = module.libstub_top;
    while (current < module.libstub_btm) {
        uint16_t size = cpu::copy_from_user(reinterpret_cast<uint16_t*>(current));
        switch (size) {
            case sizeof(ModuleImportsV1): {
                ModuleImportsV1 imports = cpu::copy_from_user(reinterpret_cast<ModuleImportsV1*>(current));
                if(library_nid == kAnyLibraryNid || imports.lib_nid == library_nid) {
                    if(find_nid_user(imports.func_nid_table, imports.func_entry_table, imports.num_functions, func_nid, out_func) == 0) {
                        return 0;
                    }
                }
                break;
            }
            case sizeof(ModuleImportsV2): {
                ModuleImportsV2 imports = cpu::copy_from_user(reinterpret_cast<ModuleImportsV2*>(current));
                if(library_nid == kAnyLibraryNid || imports.lib_nid == library_nid) {
                    if(find_nid_user(imports.func_nid_table, imports.func_entry_table, imports.num_functions, func_nid, out_func) == 0) {
                        return 0;
                    }
                }
                break;
            }
            default: {
                log::error("skipping unknown import format size=%d", size);
            }
        }
        current += size;
    }
    return kErrorNotFound;
}

} // namespace stai::modules
