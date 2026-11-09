#include "cow.h"

#include <psp2kern/kernel/sysmem.h>
#include <string.h>
#include <taihen.h>

#include "../include/stai/stai.h"
#include "cpu.h"
#include "log.h"
#include "memory.h"
#include "runtime.h"
#include "sorted_vec.h"
#include "sync.h"
#include "types.h"
#include "vec.h"

namespace stai::cow {

namespace {

constexpr u32 kL2TypeMask = 0b11;
constexpr u32 kL2TypeLarge = 0b01;
constexpr u32 kL2TypeSmall = 0b10;

constexpr u32 kL2SmallAttrMask = 0x00000FFF;
constexpr u32 kL2LargePhysMask = 0xFFFF0000;
constexpr u32 kL2LargeAttrMask = 0x0000FFFF;
constexpr u32 kL2LargeSlots = 16;

constexpr u32 kPageSize = 0x1000;
constexpr u32 kPageMask = kPageSize - 1;
constexpr u32 kPagesPerBlock = 32;
constexpr u32 kBlockSize = kPageSize * kPagesPerBlock;

struct BackingBlock {
    SceUID uid = -1;
    u32 vaddr = 0;
    u32 used_mask = 0;
};

struct PageState {
    u32 vaddr;
    u32 orig_pte;
    u32 block_index;
    u32 slot;
    u32 refcount;

    PageState(u32 vaddr, u32 orig_pte, u32 block_index, u32 slot)
        : vaddr(vaddr), orig_pte(orig_pte), block_index(block_index), slot(slot), refcount(0) {}
};

using PageVec = SortedVec<PageState, u32, &PageState::vaddr>;

struct CowRange {
    u32 addr;
    u32 size;
    SceUID uid;

    CowRange(u32 addr, u32 size, SceUID uid)
        : addr(addr), size(size), uid(uid) {}
};

using RangeVec = SortedVec<CowRange, u32, &CowRange::addr>;

struct CowProcess {
    SceUID pid;
    Vec<BackingBlock> blocks;
    PageVec pages;
    RangeVec ranges;

    explicit CowProcess(SceUID pid) : pid(pid) {}
};

using ProcessVec = SortedVec<CowProcess, SceUID, &CowProcess::pid>;

struct CowPatchObject {
    uint32_t sce_reserved[2];
    SceUID uid;
    SceUID pid;
    u32 addr;
    u32 size;
    u8* prev_data;

    static int init_object(void* data) {
        auto* object = static_cast<CowPatchObject*>(data);
        object->uid = -1;
        object->pid = 0;
        object->addr = 0;
        object->size = 0;
        object->prev_data = nullptr;
        return 0;
    }

    static int destroy_object(void* data) {
        auto* object = static_cast<CowPatchObject*>(data);
        free(object->prev_data);
        object->prev_data = nullptr;
        return 0;
    }
};

ProcessVec g_processes;
SceUID cow_lock = -1;
SceClass CowPatchObject_class;

L2PageTable* va_to_l2pagetable(AddressSpaceCommon& common, u32 vaddr) {
    u32 entry = common.l2_pagetable_vector[vaddr >> 0x14];
    if((entry & 3) != 1) {
        return nullptr;
    }
    return reinterpret_cast<L2PageTable*>(entry & ~3);
}

inline u32 l2_idx(u32 vaddr) {
    return (vaddr << 0xc) >> 0x18;
}

// Invalidate Unified TLB entry by MVA all ASID Inner Shareable
inline void tlbimvaais(u32 vaddr) {
    asm volatile ("mcr p15, 0, %0, c8, c3, 3" :: "r"(vaddr) : "memory");
}

void split_large_page(u32* pl2pte, u32 base_vaddr) {
    u32* base_pte = pl2pte + l2_idx(base_vaddr);
    u32 old_pte = *base_pte;
    u32 old_attr = old_pte & kL2LargeAttrMask;
    u32 base_paddr = old_pte & kL2LargePhysMask;
    u32 xn = (old_pte >> 15) & 0x1;
    u32 tex = (old_pte >> 12) & 0x7;
    u32 new_attr = (old_attr & kL2SmallAttrMask & ~kL2TypeMask) | (tex << 6) | xn | kL2TypeSmall;
    for(u32 i = 0; i < kL2LargeSlots; i++) {
        u32 new_pte = (base_paddr + (i * kPageSize)) | new_attr;
        asm volatile ("str %0, [%1, %2, lsl#2]" :: "r"(new_pte), "r"(base_pte), "r"(i) : "memory");
    }

    ksceKernelDcacheCleanRange(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(base_pte) & ~0x1F), 0x20);
    asm volatile ("dsb" ::: "memory");
    for(u32 i = 0; i < kL2LargeSlots; i++) {
        tlbimvaais(base_vaddr + (i * kPageSize));
    }
    asm volatile ("dsb" ::: "memory");
    asm volatile ("isb" ::: "memory");
}

int remap_page(AddressSpace& address_space, u32 vaddr, u32 new_paddr, u32& orig_pte) {
    log::debug("vaddr: %08x, new_paddr: %08x", vaddr, new_paddr);

    L2PageTable* l2table = va_to_l2pagetable(*address_space.ac, vaddr);
    if(!l2table) {
        return STAI_ERROR_REMAP;
    }

    cpu::Dacr dacr(0x17450000);

    u32 idx = l2_idx(vaddr);
    if((l2table->pl2pte[idx] & kL2TypeMask) == kL2TypeLarge) {
        split_large_page(l2table->pl2pte, vaddr & ~0xffff);
    }

    orig_pte = l2table->pl2pte[idx];
    l2table->pl2pte[idx] = new_paddr | (orig_pte & kL2SmallAttrMask);

    ksceKernelDcacheCleanRange(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&l2table->pl2pte[idx]) & ~0x1F), 0x20);
    tlbimvaais(vaddr);
    asm volatile ("dsb" ::: "memory");
    asm volatile ("isb" ::: "memory");
    return 0;
}

int restore_page(AddressSpace& address_space, u32 vaddr, u32 orig_pte) {
    L2PageTable* l2table = va_to_l2pagetable(*address_space.ac, vaddr);
    if(!l2table) {
        return STAI_ERROR_REMAP;
    }

    cpu::Dacr dacr(0x17450000);

    u32 idx = l2_idx(vaddr);
    l2table->pl2pte[idx] = orig_pte;

    ksceKernelDcacheCleanRange(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&l2table->pl2pte[idx]) & ~0x1F), 0x20);
    tlbimvaais(vaddr);
    asm volatile ("dsb" ::: "memory");
    asm volatile ("isb" ::: "memory");
    return 0;
}

bool is_shared_address(u32 addr) {
    return addr >= 0xe0000000 && addr <= 0xf0000000;
}

CowProcess* find_process(SceUID pid) {
    FindResult found = g_processes.find(pid);
    if(!found.is_found()) {
        return nullptr;
    }
    return &g_processes[found.index()];
}

CowProcess* get_or_create_process(SceUID pid) {
    FindResult found = g_processes.find(pid);
    if(found.is_found()) {
        return &g_processes[found.index()];
    }
    return g_processes.emplace_at(found, pid);
}

int alloc_block(CowProcess& process) {
    SceKernelAllocMemBlockKernelOpt opt = {
        .size = sizeof(opt),
        .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID,
        .pid = process.pid,
    };
    SceUID block_uid = ksceKernelAllocMemBlock("stai_cow", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, kBlockSize, &opt);
    if(block_uid < 0) {
        return block_uid;
    }

    int ret = ksceKernelMapMemBlock(block_uid);
    if(ret < 0) {
        ksceKernelFreeMemBlock(block_uid);
        return ret;
    }

    void* block_vaddr = nullptr;
    ret = ksceKernelGetMemBlockBase(block_uid, &block_vaddr);
    if(ret < 0) {
        ksceKernelFreeMemBlock(block_uid);
        return ret;
    }

    BackingBlock* block = process.blocks.emplace_back();
    if(block == nullptr) {
        ksceKernelFreeMemBlock(block_uid);
        return STAI_ERROR_OOM;
    }

    block->uid = block_uid;
    block->vaddr = reinterpret_cast<u32>(block_vaddr);
    block->used_mask = 0;
    return 0;
}

int alloc_slot(CowProcess& process, u32& block_index, u32& slot) {
    for(size_t i = 0; i < process.blocks.size(); i++) {
        u32 mask = process.blocks[i].used_mask;
        if(mask != 0xFFFFFFFFu) {
            slot = __builtin_ctz(~mask);
            process.blocks[i].used_mask = mask | (1u << slot);
            block_index = static_cast<u32>(i);
            return 0;
        }
    }

    int ret = alloc_block(process);
    if(ret < 0) {
        return ret;
    }

    block_index = static_cast<u32>(process.blocks.size() - 1);
    slot = 0;
    process.blocks[block_index].used_mask = 1;
    return 0;
}

void free_slot(CowProcess& process, u32 block_index, u32 slot) {
    if(block_index < process.blocks.size()) {
        process.blocks[block_index].used_mask &= ~(1u << slot);
    }
}

int prepare_page(CowProcess& process, AddressSpace& address_space, u32 page_base) {
    FindResult found = process.pages.find(page_base);
    if(found.is_found()) {
        process.pages[found.index()].refcount++;
        return 0;
    }

    u32 block_index = 0;
    u32 slot = 0;
    int ret = alloc_slot(process, block_index, slot);
    if(ret < 0) {
        return ret;
    }

    BackingBlock& block = process.blocks[block_index];
    u32 new_vaddr = block.vaddr + slot * kPageSize;
    u32 new_paddr = 0;
    ret = ksceKernelVAtoPA(reinterpret_cast<void*>(new_vaddr), &new_paddr);
    if(ret < 0) {
        free_slot(process, block_index, slot);
        return ret;
    }

    log::debug("copying page to new block: page_base=%08x, new_vaddr=%08x", page_base, new_vaddr);
    cpu::copy_from_to_user_text_domain(reinterpret_cast<void*>(new_vaddr), reinterpret_cast<void*>(page_base), kPageSize);
    ksceKernelDcacheCleanRange(reinterpret_cast<void*>(new_vaddr), kPageSize);

    u32 orig_pte = 0;
    ret = remap_page(address_space, page_base, new_paddr, orig_pte);
    if(ret < 0) {
        free_slot(process, block_index, slot);
        return ret;
    }

    PageState* state = process.pages.emplace_at(found, page_base, orig_pte, block_index, slot);
    if(state == nullptr) {
        restore_page(address_space, page_base, orig_pte);
        free_slot(process, block_index, slot);
        return STAI_ERROR_OOM;
    }
    state->refcount = 1;
    return 0;
}

void unprepare_pages(CowProcess& process, AddressSpace& address_space, u32 start, u32 end) {
    u32 page = start & ~kPageMask;
    while(page < end) {
        FindResult found = process.pages.find(page);
        if(found.is_found()) {
            PageState& state = process.pages[found.index()];
            if(state.refcount <= 1) {
                restore_page(address_space, page, state.orig_pte);
                free_slot(process, state.block_index, state.slot);
                process.pages.erase(found);
            } else {
                state.refcount--;
            }
        }
        page += kPageSize;
    }
}

bool overlaps(const CowProcess& process, u32 addr, u32 size) {
    FindResult found = process.ranges.find(addr);
    if(found.is_found()) {
        return true;
    }

    size_t index = found.index();
    if(index > 0) {
        const CowRange& previous = process.ranges[index - 1];
        if(addr < previous.addr + previous.size) {
            return true;
        }
    }
    if(index < process.ranges.size()) {
        const CowRange& next = process.ranges[index];
        if(addr + size > next.addr) {
            return true;
        }
    }
    return false;
}

void revert_page(const CowPatchObject& object, u32 page_base) {
    u32 start = object.addr > page_base ? object.addr : page_base;
    u32 object_end = object.addr + object.size;
    u32 page_end = page_base + kPageSize;
    u32 end = object_end < page_end ? object_end : page_end;
    if(start >= end) {
        return;
    }

    u32 offset = start - object.addr;
    cpu::copy_to_user_text_domain(reinterpret_cast<void*>(start), object.prev_data + offset, end - start);
    cpu::cache_flush_user(start, end - start);
}

int release_object(CowPatchObject& object, bool write_back, bool restore) {
    CowProcess* process = find_process(object.pid);
    if(process) {
        FindResult found = process->ranges.find(object.addr);
        if(found.is_found() && process->ranges[found.index()].uid == object.uid) {
            process->ranges.erase(found);
        }
    }

    auto process_object = SceObject<ProcessObject>::refer(object.pid, ksceKernelGetUIDProcessClass());
    AddressSpace* address_space = (process_object && process_object->as) ? process_object->as : nullptr;

    if(process && address_space) {
        u32 page_end = object.addr + object.size;
        for(u32 page = object.addr & ~kPageMask; page < page_end; page += kPageSize) {
            FindResult found = process->pages.find(page);
            if(!found.is_found()) {
                if(write_back) {
                    revert_page(object, page);
                }
                continue;
            }

            PageState& state = process->pages[found.index()];
            if(state.refcount <= 1) {
                if(restore) {
                    restore_page(*address_space, page, state.orig_pte);
                }
                free_slot(*process, state.block_index, state.slot);
                process->pages.erase(found);
            } else {
                state.refcount--;
                if(write_back) {
                    revert_page(object, page);
                }
            }
        }
    } else if(process) {
        u32 page_end = object.addr + object.size;
        for(u32 page = object.addr & ~kPageMask; page < page_end; page += kPageSize) {
            FindResult found = process->pages.find(page);
            if(!found.is_found()) {
                continue;
            }

            PageState& state = process->pages[found.index()];
            if(state.refcount <= 1) {
                free_slot(*process, state.block_index, state.slot);
                process->pages.erase(found);
            } else {
                state.refcount--;
            }
        }
    }
    return 0;
}

} // namespace

int init() {
    int ret = ksceUIDClassInitClass(
        &CowPatchObject_class,
        "staiCowClass",
        ksceKernelGetUIDClass(),
        sizeof(CowPatchObject),
        CowPatchObject::init_object,
        CowPatchObject::destroy_object
    );
    if(ret < 0) {
        return ret;
    }

    cow_lock = ksceKernelCreateMutex("stai_cow_lock", 0, 0, nullptr);
    if(cow_lock < 0) {
        return cow_lock;
    }
    return 0;
}

SceUID write(SceUID pid, u32 addr, const u8* data, u32 len) {
    if(len == 0 || data == nullptr) {
        return STAI_ERROR_INVALID_ARGS;
    }

    log::debug("pid=%08x, addr=%08x, len=%d", pid, addr, len);
#ifdef STAI_DEBUG
    log::debug("patch_data:");
    hex_dump(data, len);
#endif

    ScopeLock lock(cow_lock);

    auto process_object = SceObject<ProcessObject>::refer(pid, ksceKernelGetUIDProcessClass());
    if(!process_object || !process_object->as) {
        return STAI_ERROR_REMAP;
    }

    CowProcess* process = get_or_create_process(pid);
    if(process == nullptr) {
        return STAI_ERROR_OOM;
    }

    if(overlaps(*process, addr, len)) {
        log::debug("write overlaps an existing cow patch");
        return STAI_ERROR_OVERLAP;
    }

    u8* prev_data = static_cast<u8*>(malloc(len));
    if(prev_data == nullptr) {
        return STAI_ERROR_OOM;
    }
    cpu::copy_from_to_user_text_domain(prev_data, reinterpret_cast<void*>(addr), len);

    CowPatchObject* object = nullptr;
    SceGUIDKernelCreateOpt opt{};
    SceGUIDKernelCreateOpt* opt_ptr = nullptr;
    if(pid != KERNEL_PID) {
        opt.flags = 8;
        opt.pid = pid;
        opt_ptr = &opt;
    }

    int ret = ksceGUIDKernelCreateWithOpt(
        &CowPatchObject_class,
        "stai_cow",
        opt_ptr,
        reinterpret_cast<SceObjectBase**>(&object)
    );
    if(ret < 0) {
        free(prev_data);
        return ret;
    }
    SceUID uid = ret;
    object->uid = uid;
    object->pid = pid;
    object->addr = addr;
    object->size = len;
    object->prev_data = prev_data;

    u32 first_page = addr & ~kPageMask;
    u32 end = addr + len;
    u32 prepared = first_page;
    for(u32 page = first_page; page < end; page += kPageSize) {
        if(!is_shared_address(page)) {
            continue;
        }
        prepared = page;
        ret = prepare_page(*process, *process_object->as, page);
        if(ret < 0) {
            unprepare_pages(*process, *process_object->as, first_page, prepared);
            object->prev_data = nullptr;
            free(prev_data);
            ksceGUIDClose(uid);
            return ret;
        }
    }

    FindResult found = process->ranges.find(addr);
    if(process->ranges.emplace_at(found, addr, len, uid) == nullptr) {
        unprepare_pages(*process, *process_object->as, first_page, end);
        object->prev_data = nullptr;
        free(prev_data);
        ksceGUIDClose(uid);
        return STAI_ERROR_OOM;
    }

    cpu::copy_to_user_text_domain(reinterpret_cast<void*>(addr), data, len);
    cpu::cache_flush_user(addr, len);
    return uid;
}

int release(SceUID uid) {
    ScopeLock lock(cow_lock);

    int ret = 0;
    {
        auto object = SceObject<CowPatchObject>::refer(uid, &CowPatchObject_class);
        if(!object) {
            return STAI_ERROR_INVALID_ARGS;
        }

        SceKernelProcessContext* context = cpu::get_process_context(object->pid);
        if(context) {
            cpu::SwitchCtx switch_ctx(context);
            ret = release_object(*object, true, true);
        } else {
            ret = release_object(*object, false, false);
        }
    }

    ksceGUIDClose(uid);
    return ret;
}

int release_range(SceUID pid, u32 start, u32 end, bool write_back) {
    ScopeLock lock(cow_lock);

    CowProcess* process = find_process(pid);
    if(process == nullptr) {
        return 0;
    }

    Vec<SceUID> uids;
    for(const CowRange& range : process->ranges) {
        if(range.addr < end && range.addr + range.size > start) {
            if(uids.emplace_back(range.uid) == nullptr) {
                return STAI_ERROR_OOM;
            }
        }
    }

    for(SceUID uid : uids) {
        {
            auto object = SceObject<CowPatchObject>::refer(uid, &CowPatchObject_class);
            if(object) {
                release_object(*object, write_back, write_back);
            }
        }
        ksceGUIDClose(uid);
    }
    return 0;
}

void cleanup(SceUID pid) {
    ScopeLock lock(cow_lock);

    FindResult found = g_processes.find(pid);
    if(!found.is_found()) {
        return;
    }

    CowProcess& process = g_processes[found.index()];
    for(const CowRange& range : process.ranges) {
        ksceGUIDClose(range.uid);
    }
    for(const BackingBlock& block : process.blocks) {
        if(block.uid >= 0) {
            ksceKernelFreeMemBlock(block.uid);
        }
    }
    g_processes.erase(found);
}

#ifdef STAI_DEBUG
void dump_state(SceUID pid) {
    ScopeLock lock(cow_lock);

    CowProcess* process = find_process(pid);
    if(process == nullptr) {
        log::debug("no cow state pid=%08x", pid);
        return;
    }

    log::debug("cow pid=%08x", pid);
    log::debug("  blocks=%d pages=%d ranges=%d", process->blocks.size(), process->pages.size(), process->ranges.size());
    for(const BackingBlock& block : process->blocks) {
        log::debug("  block uid=%08x vaddr=%08x used=%08x", block.uid, block.vaddr, block.used_mask);
    }
    for(const PageState& page : process->pages) {
        log::debug("  page vaddr=%08x orig_pte=%08x refcount=%d", page.vaddr, page.orig_pte, page.refcount);
    }
    for(const CowRange& range : process->ranges) {
        log::debug("  range addr=%08x size=%d uid=%08x", range.addr, range.size, range.uid);
    }
}
#else
void dump_state(SceUID pid) {
    (void)pid;
}
#endif

} // namespace stai::cow
