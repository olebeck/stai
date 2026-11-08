#pragma once

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/types.h>
#include <stddef.h>
#include <string.h>

#include "log.h"
#include "runtime.h"

#define STAI_LIKELY(expr) __builtin_expect(!!(expr), 1)
#define STAI_UNLIKELY(expr) __builtin_expect(!!(expr), 0)

#define SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_SHARE_PHYPAGE 0x01000000U

namespace stai {

constexpr uint64_t kSlotsAllZero = 0;
constexpr uint64_t kSlotsFirst = 1;

constexpr size_t first_free_slot(uint64_t slots) {
    return static_cast<size_t>(__builtin_ctzll(slots));
}

constexpr bool has_one_used_slot(uint64_t slots, uint64_t empty_slot_mask) {
    const uint64_t free_mask = ~slots & empty_slot_mask;
    return free_mask != 0 && (free_mask & (free_mask - 1)) == 0;
}

constexpr bool is_power_of_two(size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

/**
 * @brief Compute the next largest power of two. Limited to 32 bits.
 */
constexpr uint32_t next_pow_2(uint32_t value) {
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value++;
    value += (value == 0);
    return value;
}

struct slab_header {
    struct slab_header* prev;
    struct slab_header* next;
    uint64_t slots;
    uintptr_t refcount;
    struct slab_header* page;
    SceUID write_uid;
    SceUID exe_uid;
    uintptr_t exe_data;
    uint8_t data[] __attribute__((aligned(sizeof(void*))));
};

constexpr void compute_slabsize_itemcount(size_t item_size, size_t& slab_size, size_t& item_count) {
    const size_t data_offset = offsetof(struct slab_header, data);
    const size_t least_slab_size = data_offset + 64 * item_size;
    slab_size = static_cast<size_t>(next_pow_2(static_cast<uint32_t>(least_slab_size)));
    item_count = 64;

    if(slab_size - least_slab_size != 0) {
        const size_t shrunk_slab_size = slab_size >> 1;
        if(data_offset < shrunk_slab_size && shrunk_slab_size - data_offset >= 2 * item_size) {
            slab_size = shrunk_slab_size;
            item_count = (shrunk_slab_size - data_offset) / item_size;
        }
    }
}

constexpr size_t compute_itemcount(size_t item_size) {
    size_t slab_size = 0;
    size_t item_count = 0;
    compute_slabsize_itemcount(item_size, slab_size, item_count);
    return item_count;
}

constexpr size_t compute_slabsize(size_t item_size) {
    size_t slab_size = 0;
    size_t item_count = 0;
    compute_slabsize_itemcount(item_size, slab_size, item_count);
    return slab_size;
}

template <size_t ITEM_SIZE>
class SlabChain {
public:
    SlabChain() : partial_(nullptr), empty_(nullptr), full_(nullptr) {}
    SlabChain(const SlabChain&) = delete;
    SlabChain& operator=(const SlabChain&) = delete;
    SlabChain(SlabChain&&) = default;
    SlabChain& operator=(SlabChain&&) = default;

    ~SlabChain() {
        struct slab_header* const heads[] = {partial_, empty_, full_};
        struct slab_header* pages_head = nullptr;
        struct slab_header* pages_tail = nullptr;

        for (size_t i = 0; i < 3; ++i) {
            struct slab_header* slab = heads[i];

            while (slab != nullptr) {
                if(slab->refcount != 0) {
                    struct slab_header* const page = slab;
                    slab = slab->next;

                    if(STAI_UNLIKELY(pages_head == nullptr)) {
                        pages_head = page;
                    } else {
                        pages_tail->next = page;
                    }

                    pages_tail = page;
                } else {
                    slab = slab->next;
                }
            }
        }

        if(STAI_LIKELY(pages_head != nullptr)) {
            pages_tail->next = nullptr;
            struct slab_header* page = pages_head;

            do {
                struct slab_header* target = page;
                page = page->next;
                sce_exe_free(target->write_uid, target->exe_uid);
            } while (page != nullptr);
        }
    }

    void* alloc(SceUID pid, uintptr_t* exe_addr) {
        if(STAI_LIKELY(partial_ != nullptr)) {
            /* found a partial slab, locate the first free slot */
            const size_t slot = first_free_slot(partial_->slots);
            partial_->slots ^= kSlotsFirst << slot;

            if(STAI_UNLIKELY(partial_->slots == kSlotsAllZero)) {
                /* slab has become full, change state from partial to full */
                struct slab_header* const tmp = partial_;

                /* skip first slab from partial list */
                if(STAI_LIKELY((partial_ = partial_->next) != nullptr)) {
                    partial_->prev = nullptr;
                }

                if(STAI_LIKELY((tmp->next = full_) != nullptr)) {
                    full_->prev = tmp;
                }

                full_ = tmp;
                *exe_addr = full_->exe_data + slot * ITEM_SIZE;
                return full_->data + slot * ITEM_SIZE;
            } else {
                *exe_addr = partial_->exe_data + slot * ITEM_SIZE;
                return partial_->data + slot * ITEM_SIZE;
            }
        } else if(STAI_LIKELY((partial_ = empty_) != nullptr)) {
            /* found an empty slab, change state from empty to partial */
            if(STAI_LIKELY((empty_ = empty_->next) != nullptr)) {
                empty_->prev = nullptr;
            }

            partial_->next = nullptr;

            /* slab is located either at the beginning of page, or beyond */
            if(STAI_UNLIKELY(partial_->refcount != 0)) {
                partial_->refcount++;
            } else {
                partial_->page->refcount++;
            }

            partial_->slots = initial_slotmask;
            *exe_addr = partial_->exe_data;
            return partial_->data;
        } else {
            /* no empty or partial slabs available, create a new one */
            SceUID write_uid;
            SceUID exe_uid;
            uintptr_t exe_data;
            void* write_data;
            int ret = sce_exe_alloc(pid, &exe_uid, &write_uid, &exe_data, &write_data, slab_size, pages_per_alloc);
            if(ret < 0) {
                return nullptr;
            }
            partial_ = reinterpret_cast<struct slab_header*>(write_data);
            partial_->write_uid = write_uid;
            partial_->exe_uid = exe_uid;
            partial_->exe_data = exe_data + offsetof(struct slab_header, data);
            exe_data += slab_size;

            struct slab_header* prev = nullptr;

            const char* const page_end = reinterpret_cast<char*>(partial_) + pages_per_alloc;

            union {
                const char* c;
                struct slab_header* const s;
            } curr = {
                .c = reinterpret_cast<const char*>(partial_) + slab_size
            };

            __builtin_prefetch(partial_, 1);

            partial_->prev = partial_->next = nullptr;
            partial_->refcount = 1;
            partial_->slots = initial_slotmask;

            if(STAI_LIKELY(curr.c != page_end)) {
                curr.s->prev = nullptr;
                curr.s->refcount = 0;
                curr.s->page = partial_;
                curr.s->write_uid = write_uid;
                curr.s->exe_uid = exe_uid;
                curr.s->exe_data = exe_data;
                exe_data += slab_size;
                curr.s->slots = empty_slotmask;
                empty_ = prev = curr.s;

                while (STAI_LIKELY((curr.c += slab_size) != page_end)) {
                    prev->next = curr.s;
                    curr.s->prev = prev;
                    curr.s->refcount = 0;
                    curr.s->page = partial_;
                    curr.s->write_uid = write_uid;
                    curr.s->exe_uid = exe_uid;
                    curr.s->exe_data = exe_data;
                    exe_data += slab_size;
                    curr.s->slots = empty_slotmask;
                    prev = curr.s;
                }

                prev->next = nullptr;
            }

            *exe_addr = partial_->exe_data;
            return partial_->data;
        }

        /* unreachable */
    }

    void free(const void* const addr) {
        struct slab_header* const slab = reinterpret_cast<struct slab_header*>(reinterpret_cast<uintptr_t>(addr) & alignment_mask);

        const int slot = (reinterpret_cast<const char*>(addr) - reinterpret_cast<char*>(slab) - offsetof(struct slab_header, data)) / ITEM_SIZE;

        if(STAI_UNLIKELY(slab->slots == kSlotsAllZero)) {
            /* target slab is full, change state to partial */
            slab->slots = kSlotsFirst << slot;

            if(STAI_LIKELY(slab != full_)) {
                if(STAI_LIKELY((slab->prev->next = slab->next) != nullptr)) {
                    slab->next->prev = slab->prev;
                }

                slab->prev = nullptr;
            } else if(STAI_LIKELY((full_ = full_->next) != nullptr)) {
                full_->prev = nullptr;
            }

            slab->next = partial_;

            if(STAI_LIKELY(partial_ != nullptr)) {
                partial_->prev = slab;
            }

            partial_ = slab;
        } else if(STAI_UNLIKELY(has_one_used_slot(slab->slots, empty_slotmask))) {
            /* target slab is partial and has only one filled slot */
            if(STAI_UNLIKELY(slab->refcount == 1 || (slab->refcount == 0 && slab->page->refcount == 1))) {
                /* unmap the whole page if this slab is the only partial one */
                if(STAI_LIKELY(slab != partial_)) {
                    if(STAI_LIKELY((slab->prev->next = slab->next) != nullptr)) {
                        slab->next->prev = slab->prev;
                    }
                } else if(STAI_LIKELY((partial_ = partial_->next) != nullptr)) {
                    partial_->prev = nullptr;
                }

                void* const page = STAI_UNLIKELY(slab->refcount != 0) ? slab : slab->page;
                const char* const page_end = reinterpret_cast<char*>(page) + pages_per_alloc;
                char found_head = 0;

                union {
                    const char* c;
                    const struct slab_header* const s;
                } s{0};

                for (s.c = reinterpret_cast<const char*>(page); s.c != page_end; s.c += slab_size) {
                    if(STAI_UNLIKELY(s.s == empty_)) {
                        found_head = 1;
                    } else if(STAI_UNLIKELY(s.s == slab)) {
                        continue;
                    } else if(STAI_LIKELY((s.s->prev->next = s.s->next) != nullptr)) {
                        s.s->next->prev = s.s->prev;
                    }
                }

                if(STAI_UNLIKELY(found_head && (empty_ = empty_->next) != nullptr)) {
                    empty_->prev = nullptr;
                }

                sce_exe_free(slab->write_uid, slab->exe_uid);
            } else {
                slab->slots = empty_slotmask;

                if(STAI_LIKELY(slab != partial_)) {
                    if(STAI_LIKELY((slab->prev->next = slab->next) != nullptr)) {
                        slab->next->prev = slab->prev;
                    }
                    slab->prev = nullptr;
                } else if(STAI_LIKELY((partial_ = partial_->next) != nullptr)) {
                    partial_->prev = nullptr;
                }

                slab->next = empty_;

                if(STAI_LIKELY(empty_ != nullptr)) {
                    empty_->prev = slab;
                }

                empty_ = slab;
                if(STAI_UNLIKELY(slab->refcount != 0)) {
                    slab->refcount--;
                } else {
                    slab->page->refcount--;
                }
            }
        } else {
            /* target slab is partial, no need to change state */
            slab->slots |= kSlotsFirst << slot;
        }
    }

    uintptr_t getmirror(const void* const addr) {
        struct slab_header* const slab =
            reinterpret_cast<struct slab_header*>(reinterpret_cast<uintptr_t>(addr) & alignment_mask);
        return slab->exe_data - offsetof(struct slab_header, data) +
               (reinterpret_cast<const char*>(addr) - reinterpret_cast<char*>(slab));
    }

private:
    static constexpr size_t slab_page_size = 0x1000;
    static constexpr size_t item_count = compute_itemcount(ITEM_SIZE);
    static constexpr size_t slab_size = compute_slabsize(ITEM_SIZE);
    static constexpr size_t pages_per_alloc = slab_size > slab_page_size ? slab_size : slab_page_size;
    static constexpr uint64_t empty_slotmask = ~kSlotsAllZero >> (64 - item_count);
    static constexpr uint64_t initial_slotmask = empty_slotmask ^ kSlotsFirst;
    static constexpr uintptr_t alignment_mask = ~(slab_size - 1);

    static_assert(ITEM_SIZE >= 1 && ITEM_SIZE <= SIZE_MAX);
    static_assert(is_power_of_two(slab_page_size));

    static int sce_exe_alloc(SceUID pid, SceUID* out_exec_uid, SceUID* out_write_uid, uintptr_t* out_exec_ptr, void** out_write_ptr, size_t align, size_t size) {
        SceKernelAllocMemBlockKernelOpt opt;
        memset(&opt, 0, sizeof(opt));
        opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
        opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID |
                   SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_ALIGNMENT |
                   0xA0000000 | 0x400000 | 0x80000;
        opt.alignment = align;
        opt.pid = pid;
        int ret = ksceKernelAllocMemBlock("exec_mem", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, size, &opt);
        if(ret < 0) {
            log::error("ksceKernelAllocMemBlock(exec_mem): %08x", ret);
            return ret;
        }
        SceUID exec_uid = ret;
        log::debug("exec_uid=%08x", exec_uid);

        ret = ksceKernelMapMemBlock(exec_uid);
        if(ret < 0) {
            log::error("ksceKernelMapMemBlock(exec_uid): %08x", ret);
            ksceKernelFreeMemBlock(exec_uid);
            return ret;
        }

        memset(&opt, 0, sizeof(opt));
        opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
        opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_MIRROR_BLOCKID |
                   SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_SHARE_PHYPAGE;
        opt.mirror_blockid = static_cast<uint32_t>(exec_uid);
        ret = ksceKernelAllocMemBlock("exec_mirror", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_TMP_RW, size, &opt);
        if(ret < 0) {
            log::error("ksceKernelAllocMemBlock(exec_mirror): %08x", ret);
            ksceKernelFreeMemBlock(exec_uid);
            return ret;
        }
        SceUID write_uid = ret;
        log::debug("write_uid=%08x", write_uid);

        void* exec_ptr;
        void* write_ptr;
        ksceKernelGetMemBlockBase(exec_uid, &exec_ptr);
        ksceKernelGetMemBlockBase(write_uid, &write_ptr);
        log::debug("exec_ptr=%p write_ptr=%p", exec_ptr, write_ptr);

        *out_exec_uid = exec_uid;
        *out_write_uid = write_uid;
        *out_exec_ptr = reinterpret_cast<uintptr_t>(exec_ptr);
        *out_write_ptr = write_ptr;
        return 0;
    }

    static int sce_exe_free(SceUID write_uid, SceUID exec_uid) {
        log::debug("freeing exec_uid=%08x write_uid=%08x", exec_uid, write_uid);
        ksceKernelFreeMemBlock(write_uid);
        ksceKernelFreeMemBlock(exec_uid);
        return 0;
    }

    struct slab_header* partial_;
    struct slab_header* empty_;
    struct slab_header* full_;
};

} // namespace stai
