#pragma once

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/types.h>
#include "std++.h"

#define SLOTS_ALL_ZERO ((uint64_t) 0)
#define SLOTS_FIRST ((uint64_t) 1)
#define FIRST_FREE_SLOT(s) ((size_t) __builtin_ctzll(s))
#define FREE_SLOTS(s) ((size_t) __builtin_popcountll(s))
#define ONE_USED_SLOT(slots, empty_slotmask) \
  ( \
    ( \
      (~(slots) & (empty_slotmask))       & \
      ((~(slots) & (empty_slotmask)) - 1)   \
    ) == SLOTS_ALL_ZERO \
  )

#define POWEROF2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

#define LIKELY(exp) __builtin_expect(exp, 1)
#define UNLIKELY(exp) __builtin_expect(exp, 0)

#define SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_SHARE_VBASE 0x00800000U
#define SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_SHARE_PHYPAGE 0x01000000U


/**
 * @brief      Compute the next largest power of two. Limit 32 bits.
 *
 * @param[in]  v     Input number
 *
 * @return     Next power of 2.
 */
constexpr uint32_t next_pow_2(uint32_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  v += (v == 0);
  return v;
}

struct slab_header {
  struct slab_header *prev, *next;
  uint64_t slots;
  uintptr_t refcount;
  struct slab_header *page;
  SceUID write_uid;
  SceUID exe_uid;
  uintptr_t exe_data;
  uint8_t data[] __attribute__((aligned(sizeof(void *))));
};

constexpr void compute_slabsize_itemcount(size_t itemsize, size_t& slabsize, size_t& itemcount) {
  const size_t data_offset = offsetof(struct slab_header, data);
  const size_t least_slabsize = data_offset + 64 * itemsize;
  slabsize = (size_t) next_pow_2(least_slabsize);
  itemcount = 64;

  if (slabsize - least_slabsize != 0) {
    const size_t shrinked_slabsize = slabsize >> 1;
    if (data_offset < shrinked_slabsize &&
      shrinked_slabsize - data_offset >= 2 * itemsize) {
      slabsize = shrinked_slabsize;
      itemcount = (shrinked_slabsize - data_offset) / itemsize;
    }
  }
}

constexpr auto compute_itemcount(size_t itemsize) {
  size_t slabsize = 0, itemcount = 0;
  compute_slabsize_itemcount(itemsize, slabsize, itemcount);
  return itemcount;
}

constexpr auto compute_slabsize(size_t itemsize) {
  size_t slabsize = 0, itemcount = 0;
  compute_slabsize_itemcount(itemsize, slabsize, itemcount);
  return slabsize;
}

template<size_t ITEMSIZE>
class SlabChain {
private:
  struct slab_header *partial, *empty, *full;

  static constexpr size_t slab_pagesize = 0x1000;
  static constexpr size_t itemcount = compute_itemcount(ITEMSIZE);
  static constexpr size_t slabsize = compute_slabsize(ITEMSIZE);
  static constexpr size_t pages_per_alloc  = slabsize > slab_pagesize ? slabsize : slab_pagesize;
  static constexpr uint64_t empty_slotmask = ~SLOTS_ALL_ZERO >> (64 - itemcount);
  static constexpr uint64_t initial_slotmask = empty_slotmask ^ SLOTS_FIRST;
  static constexpr uintptr_t alignment_mask  = ~(slabsize - 1);

  static_assert(ITEMSIZE >= 1 && ITEMSIZE <= SIZE_MAX);
  static_assert(POWEROF2(slab_pagesize));

  static int sce_exe_alloc(SceUID pid, SceUID* exec_uid, SceUID* write_uid, uintptr_t* exec_ptr, void** write_ptr, size_t align, size_t size) {
    *exec_uid = -1;
    *write_uid = -1;
    *exec_ptr = 0;
    *write_ptr = NULL;
    
    // allocate executable
    SceKernelAllocMemBlockKernelOpt opt;
    memset(&opt, 0, sizeof(opt));
    opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
    opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID | SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_ALIGNMENT | 0xA0000000 | 0x400000 | 0x80000;
    opt.alignment = align;
    opt.pid = pid;
    int ret = ksceKernelAllocMemBlock("exec_mem", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RX, size, &opt);
    if(ret < 0) {
      LOGE("ksceKernelAllocMemBlock(exec_mem): %08x", ret);
      goto error;
    }
    *exec_uid = ret;
    LOGD("exec_uid=%08x", *exec_uid);

    ret = ksceKernelMapMemBlock(*exec_uid);
    if(ret < 0) {
      LOGE("ksceKernelMapMemBlock(exec_uid): %08x", ret);
      goto error;
    }

    // allocate kernel mirror
    memset(&opt, 0, sizeof(opt));
    opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
    opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_MIRROR_BLOCKID | SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_SHARE_PHYPAGE;
    opt.mirror_blockid = (uint32_t)(*exec_uid);
    ret = ksceKernelAllocMemBlock("exec_mirror", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_TMP_RW, size, &opt);
    if(ret < 0) {
      LOGE("ksceKernelAllocMemBlock(exec_mirror): %08x", ret);
      goto error;
    }
    *write_uid = ret;
    LOGD("write_uid=%08x", *write_uid);

    ksceKernelGetMemBlockBase(*exec_uid, (void**)exec_ptr);
    ksceKernelGetMemBlockBase(*write_uid, write_ptr);
    LOGD("exec_ptr=%p write_ptr=%p", (void*)*exec_ptr, *write_ptr);
    return 0;
  error:
    if(*exec_uid > 0) {
      ksceKernelFreeMemBlock(*exec_uid);
    }
    if(*write_uid > 0) {
      ksceKernelFreeMemBlock(*write_uid);
    }
    return ret;
  }

  static int sce_exe_free(SceUID write_uid, SceUID exec_uid) {
    LOGD("freeing exec_uid=%08x write_uid=%08x", exec_uid, write_uid);
    ksceKernelFreeMemBlock(write_uid);
    ksceKernelFreeMemBlock(exec_uid);
    return 0;
  }

public:
  SlabChain() : partial(nullptr), empty(nullptr), full(nullptr) {}
  SlabChain(const SlabChain&) = delete;
  SlabChain& operator=(const SlabChain&) = delete;
  SlabChain(SlabChain&&) = default;
  SlabChain& operator=(SlabChain&&) = default;

  ~SlabChain() {
    struct slab_header *const heads[] = {this->partial, this->empty, this->full};
    struct slab_header *pages_head = NULL;
    struct slab_header *pages_tail = NULL;

    for (size_t i = 0; i < 3; ++i) {
      struct slab_header *slab = heads[i];

      while (slab != NULL) {
        if (slab->refcount != 0) {
          struct slab_header *const page = slab;
          slab = slab->next;

          if (UNLIKELY(pages_head == NULL)) {
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

    if (LIKELY(pages_head != NULL)) {
      pages_tail->next = NULL;
      struct slab_header *page = pages_head;

      do {
        struct slab_header *target = page;
        page = page->next;
        sce_exe_free(target->write_uid, target->exe_uid);
      } while (page != NULL);
    }
  }

  void *alloc(SceUID pid, uintptr_t *exe_addr) {
    if (LIKELY(this->partial != NULL)) {
      /* found a partial slab, locate the first free slot */
      const size_t slot = FIRST_FREE_SLOT(this->partial->slots);
      this->partial->slots ^= SLOTS_FIRST << slot;

      if (UNLIKELY(this->partial->slots == SLOTS_ALL_ZERO)) {
        /* slab has become full, change state from partial to full */
        struct slab_header *const tmp = this->partial;

        /* skip first slab from partial list */
        if (LIKELY((this->partial = this->partial->next) != NULL)) {
          this->partial->prev = NULL;
        }

        if (LIKELY((tmp->next = this->full) != NULL)) {
          this->full->prev = tmp;
        }

        this->full = tmp;
        *exe_addr = this->full->exe_data + slot * ITEMSIZE;
        return this->full->data + slot * ITEMSIZE;
      } else {
        *exe_addr = this->partial->exe_data + slot * ITEMSIZE;
        return this->partial->data + slot * ITEMSIZE;
      }
    } else if (LIKELY((this->partial = this->empty) != NULL)) {
      /* found an empty slab, change state from empty to partial */
      if (LIKELY((this->empty = this->empty->next) != NULL)) {
        this->empty->prev = NULL;
      }

      this->partial->next = NULL;

      /* slab is located either at the beginning of page, or beyond */
      if(UNLIKELY(this->partial->refcount != 0)) {
        this->partial->refcount++;
      } else {
        this->partial->page->refcount++;
      }

      this->partial->slots = this->initial_slotmask;
      *exe_addr = this->partial->exe_data;
      return this->partial->data;
    } else {
      /* no empty or partial slabs available, create a new one */
      SceUID write_uid, exe_uid;
      uintptr_t exe_data;
      int ret = sce_exe_alloc(pid, &exe_uid, &write_uid, &exe_data, (void **)&this->partial, this->slabsize, this->pages_per_alloc);
      if (ret < 0) {
        *exe_addr = 0;
        this->partial = NULL;
        return NULL;
      }
      this->partial->write_uid = write_uid;
      this->partial->exe_uid = exe_uid;
      this->partial->exe_data = exe_data + offsetof(struct slab_header, data);
      exe_data += this->slabsize;

      struct slab_header *prev = NULL;

      const char *const page_end = (char *) this->partial + this->pages_per_alloc;

      union {
        const char *c;
        struct slab_header *const s;
      } curr = {
        .c = (const char *) this->partial + this->slabsize
      };

      __builtin_prefetch(this->partial, 1);

      this->partial->prev = this->partial->next = NULL;
      this->partial->refcount = 1;
      this->partial->slots = this->initial_slotmask;

      if (LIKELY(curr.c != page_end)) {
        curr.s->prev = NULL;
        curr.s->refcount = 0;
        curr.s->page = this->partial;
        curr.s->write_uid = write_uid;
        curr.s->exe_uid = exe_uid;
        curr.s->exe_data = exe_data;
        exe_data += this->slabsize;
        curr.s->slots = this->empty_slotmask;
        this->empty = prev = curr.s;

        while (LIKELY((curr.c += this->slabsize) != page_end)) {
          prev->next = curr.s;
          curr.s->prev = prev;
          curr.s->refcount = 0;
          curr.s->page = this->partial;
          curr.s->write_uid = write_uid;
          curr.s->exe_uid = exe_uid;
          curr.s->exe_data = exe_data;
          exe_data += this->slabsize;
          curr.s->slots = this->empty_slotmask;
          prev = curr.s;
        }

        prev->next = NULL;
      }

      *exe_addr = this->partial->exe_data;
      return this->partial->data;
    }

    /* unreachable */
  }

  void free(const void *const addr) {
    struct slab_header *const slab = (struct slab_header *const)(void*)((uintptr_t) addr & this->alignment_mask);

    const int slot = ((char *) addr - (char *) slab - offsetof(struct slab_header, data)) / ITEMSIZE;

    if (UNLIKELY(slab->slots == SLOTS_ALL_ZERO)) {
      /* target slab is full, change state to partial */
      slab->slots = SLOTS_FIRST << slot;

      if (LIKELY(slab != this->full)) {
        if (LIKELY((slab->prev->next = slab->next) != NULL)) {
          slab->next->prev = slab->prev;
        }

        slab->prev = NULL;
      } else if (LIKELY((this->full = this->full->next) != NULL)) {
        this->full->prev = NULL;
      }

      slab->next = this->partial;

      if (LIKELY(this->partial != NULL)) {
        this->partial->prev = slab;
      }

      this->partial = slab;
    } else if (UNLIKELY(ONE_USED_SLOT(slab->slots, this->empty_slotmask))) {
      /* target slab is partial and has only one filled slot */
      if (UNLIKELY(slab->refcount == 1 || (slab->refcount == 0 && slab->page->refcount == 1))) {

        /* unmap the whole page if this slab is the only partial one */
        if (LIKELY(slab != this->partial)) {
          if (LIKELY((slab->prev->next = slab->next) != NULL)) {
            slab->next->prev = slab->prev;
          }
        } else if (LIKELY((this->partial = this->partial->next) != NULL)) {
          this->partial->prev = NULL;
        }

        void *const page = UNLIKELY(slab->refcount != 0) ? slab : slab->page;
        const char *const page_end = (char *) page + this->pages_per_alloc;
        char found_head = 0;

        union {
          const char *c;
          const struct slab_header *const s;
        } s{0};

        for (s.c = (const char*)page; s.c != page_end; s.c += this->slabsize) {
          if (UNLIKELY(s.s == this->empty)) {
            found_head = 1;
          } else if (UNLIKELY(s.s == slab)) {
            continue;
          } else if (LIKELY((s.s->prev->next = s.s->next) != NULL)) {
            s.s->next->prev = s.s->prev;
          }
        }

        if (UNLIKELY(found_head && (this->empty = this->empty->next) != NULL)) {
          this->empty->prev = NULL;
        }

        sce_exe_free(slab->write_uid, slab->exe_uid);
      } else {
        slab->slots = this->empty_slotmask;

        if (LIKELY(slab != this->partial)) {
          if (LIKELY((slab->prev->next = slab->next) != NULL)) {
            slab->next->prev = slab->prev;
          }
          slab->prev = NULL;
        } else if (LIKELY((this->partial = this->partial->next) != NULL)) {
          this->partial->prev = NULL;
        }

        slab->next = this->empty;

        if (LIKELY(this->empty != NULL)) {
          this->empty->prev = slab;
        }

        this->empty = slab;
        if(UNLIKELY(slab->refcount != 0)) {
          slab->refcount--;
        } else {
          slab->page->refcount--;
        }
      }
    } else {
      /* target slab is partial, no need to change state */
      slab->slots |= SLOTS_FIRST << slot;
    }
  }

  uintptr_t getmirror(const void *const addr) {
    struct slab_header *const slab = (struct slab_header *const)(void *)((uintptr_t) addr & this->alignment_mask);
    return slab->exe_data - offsetof(struct slab_header, data) + (ptrdiff_t)((char *) addr - (char *) slab);
  }
};
