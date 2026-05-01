#ifndef __STAI_H__
#define __STAI_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <psp2common/types.h>

#define STAI_ERROR_BASE           (0x91000000)
#define STAI_ERROR_FUNC_TOO_SHORT (STAI_ERROR_BASE + 1)
#define STAI_ERROR_FUNC_BAD_INSN  (STAI_ERROR_BASE + 2)
#define STAI_ERROR_FUNC_CALLS     (STAI_ERROR_BASE + 3)
#define STAI_ERROR_FUNC_JUMPS     (STAI_ERROR_BASE + 4)

#define STAI_ERROR_MEMORY         (STAI_ERROR_BASE + 0x11)
#define STAI_ERROR_NOT_FOUND      (STAI_ERROR_BASE + 0x12)
#define STAI_ERROR_UNEXPECTED     (STAI_ERROR_BASE + 0x13)
#define STAI_ERROR_REMAP          (STAI_ERROR_BASE + 0x14)
#define STAI_ERROR_OOM            (STAI_ERROR_BASE + 0x15)
#define STAI_ERROR_INVALID_ARGS   (STAI_ERROR_BASE + 0x16)
#define STAI_SUCCESS              (0)

#define STAI_MAIN_MODULE (0)

#define STAI_INLINE __attribute__((always_inline)) inline

typedef struct stai_ref_t {
  void* next;
  void* func;
  void* old;
  uint32_t reserved[5];
} stai_ref_t;

typedef struct stai_module_info {
  size_t size;
  SceUID module_uid;
  uint32_t fingerprint;
  uint32_t text_base;
  uint32_t text_size;
} stai_module_info;

#define STAI_CONTINUE(fn, hook, ...) ({ \
  struct stai_ref_t *cur = hook; \
  struct stai_ref_t *next = (stai_ref_t *)cur->next; \
  typedef __typeof__(fn) *_fn_ptr_type; \
  (next == NULL)  ? \
    ((_fn_ptr_type)(cur->old))(__VA_ARGS__) \
  : \
    ((_fn_ptr_type)(next->func))(__VA_ARGS__) \
  ; \
})

#define STAI_HOOK(ret_type, name, params...) \
  static stai_ref_t name##_hook_ref; \
  static ret_type name##_hook(params)

#define STAI_HOOK_CONTINUE(name, ...) STAI_CONTINUE(name##_hook, &name##_hook_ref, __VA_ARGS__)

typedef struct _stai_hook_offset_args {
  size_t      size;        // size of this struct
  SceUID      module_uid;  // module uid of the target module
  uint32_t    offset;      // address of the target function, relative to the module text segment base addr | 1 for thumb mode
  uintptr_t   dest_func;   // the destination function, must not be null
  stai_ref_t* ref;         // must not be null
} _stai_hook_offset_args;

typedef struct _stai_hook_nid_args {
  size_t      size;        // size of this struct
  SceUID      module_uid;  // module uid of the target module
  uint32_t    library_nid; // nid of the library where the target function is exported/imported
  uint32_t    func_nid;    // nid of the target function
  uintptr_t   dest_func;   // the destination function, must not be null
  stai_ref_t* ref;         // must not be null
} _stai_hook_nid_args;

typedef struct _stai_hook_module_start_args {
  size_t      size;        // size of this struct
  uint32_t    library_nid; // nid of a library in the target module
  uintptr_t   dest_func;   // the destination function
  stai_ref_t* ref;         // must not be null
} _stai_hook_module_start_args;

// syscalls
int _staiHookExport(const _stai_hook_nid_args* args);
int _staiHookImport(const _stai_hook_nid_args* args);
int _staiHookOffset(const _stai_hook_offset_args* args);
int _staiUnhook(stai_ref_t* ref);
int _staiHookModuleStart(const _stai_hook_module_start_args* args);
int _staiFindModuleByLibraryNid(uint32_t library_nid, stai_module_info* out_module_info);

// ref MUST be static
STAI_INLINE int staiHookOffset(SceUID module_uid, uint32_t offset, int thumb, void* dest_func, stai_ref_t* ref) {
  _stai_hook_offset_args args = {
    .size = sizeof(_stai_hook_offset_args),
    .module_uid = module_uid,
    .offset = offset | (thumb ? 1 : 0),
    .dest_func = (uintptr_t)dest_func,
    .ref = ref
  };
  return _staiHookOffset(&args);
}

// ref MUST be static
STAI_INLINE int staiHookExport(SceUID module_uid, uint32_t library_nid, uint32_t func_nid, void* dest_func, stai_ref_t* ref) {
  _stai_hook_nid_args args = {
    .size = sizeof(_stai_hook_nid_args),
    .module_uid = module_uid,
    .library_nid = library_nid,
    .func_nid = func_nid,
    .dest_func = (uintptr_t)dest_func,
    .ref = ref
  };
  return _staiHookExport(&args);
}

// ref MUST be static
STAI_INLINE int staiHookImport(SceUID module_uid, uint32_t library_nid, uint32_t func_nid, void* dest_func, stai_ref_t* ref) {
  _stai_hook_nid_args args = {
    .size = sizeof(_stai_hook_nid_args),
    .module_uid = module_uid,
    .library_nid = library_nid,
    .func_nid = func_nid,
    .dest_func = (uintptr_t)dest_func,
    .ref = ref
  };
  return _staiHookImport(&args);
}

STAI_INLINE int staiUnhook(stai_ref_t* ref) {
  return _staiUnhook(ref);
}

// ref MUST be static
STAI_INLINE int staiHookModuleStart(uint32_t library_nid, void* dest_func, stai_ref_t* ref) {
  _stai_hook_module_start_args args = {
    .size = sizeof(_stai_hook_module_start_args),
    .library_nid = library_nid,
    .dest_func = (uintptr_t)dest_func,
    .ref = ref,
  };
  return _staiHookModuleStart(&args);
}

// returns the module id of the module that exports the library with the given nid
// returns 0 if not found, or a negative error code on failure
STAI_INLINE int staiFindModuleByLibraryNid(uint32_t library_nid, stai_module_info* out_module_info) {
  return _staiFindModuleByLibraryNid(library_nid, out_module_info);
}

#ifdef __cplusplus
}
#endif

#endif
