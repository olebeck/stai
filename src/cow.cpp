#include "cow.h"

const u32 L2_TYPE_MASK = 0x3;
const u32 L2_TYPE_LARGE = 0x1;
const u32 L2_TYPE_SMALL = 0x2;

const u32 L2_SMALL_ATTR_MASK = 0x00000FFF;
const u32 L2_LARGE_PHYS_MASK = 0xFFFF0000;
const u32 L2_LARGE_ATTR_MASK = 0x0000FFFF;
const u32 L2_LARGE_SLOTS = 16;
const u32 PAGE_SIZE = 0x1000;

static SceAddressSpace* get_process_address_space(SceUID pid) {
    SceObjectBase* object;
    int ret = ksceGUIDReferObject(pid, &object);
    if(ret < 0) {
        return nullptr;
    }
    SceUIDProcessObject* process = (SceUIDProcessObject*)object;
    ksceGUIDReleaseObject(pid);
    return process->as;
}

static L2PageTable* va_to_l2pagetable(AsCommon& ac, u32 vaddr) {
    u32 entry = ac.l2_pagetable_vector[vaddr >> 0x14];
    if((entry & 3) != 1) {
        return nullptr;
    }
    return reinterpret_cast<L2PageTable*>(entry & ~3);
}

static u32 inline_always l2_idx(u32 vaddr) {
    return (vaddr << 0xc) >> 0x18;
}

// Invalidate Unified TLB entry by MVA all ASID Inner Shareable
static inline void TLBIMVAAIS(u32 vaddr) {
    asm volatile("mcr p15, 0, %0, c8, c3, 3" :: "r"(vaddr) : "memory");
}

static void split_large_page(u32* pl2pte, u32 base_vaddr) {
    u32* base_pte = pl2pte + l2_idx(base_vaddr);
    u32 old_pte = *base_pte;
    u32 old_attr = old_pte & L2_LARGE_ATTR_MASK;
    u32 base_paddr = old_pte & L2_LARGE_PHYS_MASK;
    u32 xn = (old_pte >> 15) & 0x1;
    u32 tex = (old_pte >> 12) & 0x7;
    u32 new_attr = (old_attr & L2_SMALL_ATTR_MASK & ~L2_TYPE_MASK) | (tex << 6) | xn | L2_TYPE_SMALL;
    for(u32 i = 0; i < L2_LARGE_SLOTS; i++) {
        u32 new_pte = (base_paddr + (i * PAGE_SIZE)) | new_attr;
        asm volatile("str %0, [%1, %2, lsl#2]" ::"r"(new_pte), "r"(base_pte), "r"(i) : "memory");
    }

    ksceKernelDcacheCleanRange((void*)((u32)base_pte & ~0x1F), 0x20);
    asm volatile("dsb" ::: "memory");
    for(u32 i = 0; i < L2_LARGE_SLOTS; i++) {
        u32 vaddr = base_vaddr + (i * PAGE_SIZE);
        TLBIMVAAIS(vaddr);
    }
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
}

static int remap_page(SceAddressSpace& as, u32 vaddr, u32 new_paddr, u32& orig_pte) {
    LOGD("vaddr: %08x, new_paddr: %08x", vaddr, new_paddr);

    L2PageTable* l2table = va_to_l2pagetable(*as.ac, vaddr);
    if(!l2table) {
        return STAI_ERROR_REMAP;
    }

    SuspendIntr intr;
    Dacr dacr(0x17450000);
    
    u32 idx = l2_idx(vaddr);
    if((l2table->pl2pte[idx] & L2_TYPE_MASK) == L2_TYPE_LARGE) {
        split_large_page(l2table->pl2pte, vaddr & ~0xffff);
    }

    orig_pte = l2table->pl2pte[idx];
    l2table->pl2pte[idx] = new_paddr | (orig_pte & L2_SMALL_ATTR_MASK);

    ksceKernelDcacheCleanRange((void*)((u32)(&l2table->pl2pte[idx]) & ~0x1F), 0x20);
    TLBIMVAAIS(vaddr);
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
    return 0;
}

static int print_pte(SceAddressSpace& as, u32 vaddr) {
    L2PageTable* l2table = va_to_l2pagetable(*as.ac, vaddr);
    if(!l2table) {
        return STAI_ERROR_REMAP;
    }

    SuspendIntr intr;
    Dacr dacr(0x17450000);
    u32 pte = l2table->pl2pte[l2_idx(vaddr)];
    LOGD("vaddr: %08x pte: %08x", vaddr, pte);
    return 0;
}

static int restore_page(SceAddressSpace& as, u32 vaddr, u32 orig_pte) {
    L2PageTable* l2table = va_to_l2pagetable(*as.ac, vaddr);
    if(!l2table) {
        return STAI_ERROR_REMAP;
    }
    
    SuspendIntr intr;
    Dacr dacr(0x17450000);
    
    u32 idx = l2_idx(vaddr);
    l2table->pl2pte[idx] = orig_pte;

    ksceKernelDcacheCleanRange((void*)((u32)(&l2table->pl2pte[idx]) & ~0x1F), 0x20);
    TLBIMVAAIS(vaddr);
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
    return 0;
}

static int cow_write(CtxSwitched& sw, SceAddressSpace& as, PageRemapVec& remaps, u32 addr, u8* data, u32 len) {
    u32 remaining = len;
    u32 current_vaddr = addr;
    u8* current_data = data;

    while(remaining > 0) {
        u32 page_base = current_vaddr & ~0xfff;
        u32 page_offset = current_vaddr & 0xfff;
        u32 copy_size = (0x1000 - page_offset);
        if(copy_size > remaining) {
            copy_size = remaining;
        }

        auto find = remaps.find(page_base);
        if(!find.is_found()) {
            SceKernelAllocMemBlockKernelOpt opt = {
                .size = sizeof(opt),
                .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID,
                .pid = as.pid,
            };
            SceUID block_uid = ksceKernelAllocMemBlock("stai_cow", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, 0x1000, &opt);
            if(block_uid < 0) {
                return block_uid;
            }
            ksceKernelMapMemBlock(block_uid);
            PageRemap* remap = remaps.emplace_at(find, page_base, block_uid);
            if(remap == nullptr) {
                ksceKernelFreeMemBlock(block_uid);
                return STAI_ERROR_OOM;
            }

            void* new_vaddr;
            u32 new_paddr;
            ksceKernelGetMemBlockBase(block_uid, &new_vaddr);
            ksceKernelVAtoPA(new_vaddr, &new_paddr);

            LOGD("copying page to new block: page_base=%08x, new_vaddr=%08x", page_base, new_vaddr);
            copy_from_to_user_text_domain(sw, new_vaddr, (void*)page_base, 0x1000);
            ksceKernelDcacheCleanRange(new_vaddr, 0x1000);

            int ret = remap_page(as, page_base, new_paddr, remap->orig_pte);
            if(ret < 0) {
                return ret;
            }
        }

        LOGD("copying patch: vaddr=%08x, dst=%p, size=%d", page_base, current_vaddr, copy_size);
        copy_to_user_text_domain(sw, (void*)current_vaddr, current_data, copy_size);

        current_data += copy_size;
        current_vaddr += copy_size;
        remaining -= copy_size;
    }
    return 0;
}

static bool is_shared_address(u32 addr) {
    return addr >= 0xe0000000 && addr <= 0xf0000000;
}

int write_user_text(CtxSwitched& sw, SceUID pid, PageRemapVec& remaps, u32 dst, u8* data, u32 len) {
    LOGD("dst=%08x, data=%p, len=%d", dst, data, len);
#ifdef DEBUG
    LOGD("patch_data:");
    hex_dump(data, len);
#endif
    if(is_shared_address(dst)) {
        SceAddressSpace* as = get_process_address_space(pid);
        if(!as) {
            return STAI_ERROR_REMAP;
        }
        return cow_write(sw, *as, remaps, dst, data, len);
    } else {
        copy_to_user_text_domain(sw, (void*)dst, data, len);
        const auto [dst_align, len_align] = align_cache_line(dst, len);
        ksceKernelDcacheCleanInvalidateRange((void*)dst_align, len_align);
        return 0;
    }
}

void restore_pages(SceUID pid, PageRemapVec::Slice& slice) {
    SceAddressSpace* as = get_process_address_space(pid);
    for(PageRemap& remap : slice) {
        if(remap.orig_pte) {
            restore_page(*as, remap.target_vaddr, remap.orig_pte);
        }
        if(remap.block_uid) {
            ksceKernelFreeMemBlock(remap.block_uid);
        }
    }
}
