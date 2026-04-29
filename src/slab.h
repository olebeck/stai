#ifndef _SLAB_H_
#define _SLAB_H_

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

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

struct slab_chain {
  size_t itemsize, itemcount;
  size_t slabsize, pages_per_alloc;
  uint64_t initial_slotmask, empty_slotmask;
  uintptr_t alignment_mask;
  struct slab_header *partial, *empty, *full;
  SceUID pid;
};

void slab_init(struct slab_chain* sch, size_t itemsize, SceUID pid);
void *slab_alloc(struct slab_chain* sch, uintptr_t* exe_addr);
void slab_free(struct slab_chain* sch, const void* addr);
uintptr_t slab_getmirror(struct slab_chain* sch, const void* addr);
void slab_traverse(const struct slab_chain* sch, void (*func)(const void *));
void slab_destroy(const struct slab_chain* sch);

#ifdef __cplusplus
}
#endif

#endif
