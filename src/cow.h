#pragma once

#include <psp2kern/kernel/cpu.h>

#include "../include/stai/stai.h"
#include "std++.h"
#include "types.h"
#include "cpu.h"

struct PageRemap {
    u32 target_vaddr;
    u32 orig_pte;
    SceUID block_uid;

    PageRemap(u32 target_vaddr, SceUID block_uid) :
        target_vaddr(target_vaddr), orig_pte(0), block_uid(block_uid) {}
    PageRemap(const PageRemap&) = delete;
    PageRemap& operator=(const PageRemap&) = delete;
    PageRemap(PageRemap&&) = default;
    PageRemap& operator=(PageRemap&&) = default;
};

typedef SortedVec<PageRemap, u32, &PageRemap::target_vaddr> PageRemapVec;

int write_user_text(CtxSwitched& sw, SceUID pid, PageRemapVec& remaps, u32 dst, u8* data, u32 len);

void restore_pages(SceUID pid, PageRemapVec::Slice& slice);
