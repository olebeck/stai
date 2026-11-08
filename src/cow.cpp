#include "cow.h"

#include "log.h"
#include "runtime.h"

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
    for (u32 i = 0; i < kL2LargeSlots; i++) {
        u32 new_pte = (base_paddr + (i * kPageSize)) | new_attr;
        asm volatile ("str %0, [%1, %2, lsl#2]" :: "r"(new_pte), "r"(base_pte), "r"(i) : "memory");
    }

    ksceKernelDcacheCleanRange(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(base_pte) & ~0x1F), 0x20);
    asm volatile ("dsb" ::: "memory");
    for (u32 i = 0; i < kL2LargeSlots; i++) {
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

int cow_write(AddressSpace& address_space, PageRemapVec& remaps, u32 addr, const u8* data, u32 len) {
    u32 remaining = len;
    u32 current_vaddr = addr;
    const u8* current_data = data;

    while (remaining > 0) {
        u32 page_base = current_vaddr & ~0xfff;
        u32 page_offset = current_vaddr & 0xfff;
        u32 copy_size = kPageSize - page_offset;
        if(copy_size > remaining) {
            copy_size = remaining;
        }

        auto found = remaps.find(page_base);
        if(!found.is_found()) {
            SceKernelAllocMemBlockKernelOpt opt = {
                .size = sizeof(opt),
                .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID,
                .pid = address_space.pid,
            };
            SceUID block_uid = ksceKernelAllocMemBlock("stai_cow", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, kPageSize, &opt);
            if(block_uid < 0) {
                return block_uid;
            }
            int ret = ksceKernelMapMemBlock(block_uid);
            if(ret < 0) {
                ksceKernelFreeMemBlock(block_uid);
                return ret;
            }

            void* new_vaddr;
            u32 new_paddr;
            ret = ksceKernelGetMemBlockBase(block_uid, &new_vaddr);
            if(ret < 0) {
                ksceKernelFreeMemBlock(block_uid);
                return ret;
            }
            ret = ksceKernelVAtoPA(new_vaddr, &new_paddr);
            if(ret < 0) {
                ksceKernelFreeMemBlock(block_uid);
                return ret;
            }

            PageRemap* remap = remaps.emplace_at(found, page_base, block_uid);
            if(remap == nullptr) {
                ksceKernelFreeMemBlock(block_uid);
                return STAI_ERROR_OOM;
            }

            log::debug("copying page to new block: page_base=%08x, new_vaddr=%08x", page_base, new_vaddr);
            cpu::copy_from_to_user_text_domain(new_vaddr, reinterpret_cast<void*>(page_base), kPageSize);
            ksceKernelDcacheCleanRange(new_vaddr, kPageSize);

            ret = remap_page(address_space, page_base, new_paddr, remap->orig_pte);
            if(ret < 0) {
                remaps.erase(page_base);
                ksceKernelFreeMemBlock(block_uid);
                return ret;
            }
        }

        log::debug("copying patch: vaddr=%08x, dst=%p, size=%d", page_base, current_vaddr, copy_size);
        cpu::copy_to_user_text_domain(reinterpret_cast<void*>(current_vaddr), current_data, copy_size);
        cpu::cache_flush_user(current_vaddr, copy_size);

        current_data += copy_size;
        current_vaddr += copy_size;
        remaining -= copy_size;
    }
    return 0;
}

bool is_shared_address(u32 addr) {
    return addr >= 0xe0000000 && addr <= 0xf0000000;
}

} // namespace

int write_user_text(SceUID pid, PageRemapVec& remaps, u32 dst, const u8* data, u32 len) {
    log::debug("dst=%08x, data=%p, len=%d", dst, data, len);
#ifdef STAI_DEBUG
    log::debug("patch_data:");
    hex_dump(data, len);
#endif
    if(is_shared_address(dst)) {
        auto process = SceObject<ProcessObject>::refer(pid);
        if(!process) {
            return STAI_ERROR_REMAP;
        }
        return cow_write(*process->as, remaps, dst, data, len);
    }

    cpu::copy_to_user_text_domain(reinterpret_cast<void*>(dst), data, len);
    cpu::cache_flush_user(dst, len);
    return 0;
}

void restore_pages(SceUID pid, PageRemapVec::Slice& slice) {
    auto process = SceObject<ProcessObject>::refer(pid);
    for (PageRemap& remap : slice) {
        if(process && remap.orig_pte) {
            restore_page(*process->as, remap.target_vaddr, remap.orig_pte);
        }
        if(remap.block_uid) {
            ksceKernelFreeMemBlock(remap.block_uid);
        }
    }
}

} // namespace stai::cow
