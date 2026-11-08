#pragma once

#include <psp2kern/kernel/cpu.h>

#include "../include/stai/stai.h"
#include "cpu.h"
#include "sorted_vec.h"
#include "types.h"

namespace stai::cow {

struct PageRemap {
    u32 target_vaddr;
    SceUID block_uid;
    u32 orig_pte;

    PageRemap(u32 target_vaddr, SceUID block_uid)
        : target_vaddr(target_vaddr), block_uid(block_uid), orig_pte(0) {}

    PageRemap(const PageRemap&) = delete;
    PageRemap& operator=(const PageRemap&) = delete;
    PageRemap(PageRemap&&) = default;
    PageRemap& operator=(PageRemap&&) = default;
};

using PageRemapVec = SortedVec<PageRemap, u32, &PageRemap::target_vaddr>;

int write_user_text(SceUID pid, PageRemapVec& remaps, u32 dst, const u8* data, u32 len);

void restore_pages(SceUID pid, PageRemapVec::Slice& slice);

} // namespace stai::cow
