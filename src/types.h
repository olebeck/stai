#ifndef _TYPES_H_
#define _TYPES_H_

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>

typedef struct SceModuleCB SceModuleCB;

typedef struct SceModuleExport {
  uint8_t size;
  uint8_t auxattr;
  uint16_t version;
  uint16_t flags;
  uint16_t num_function;
  uint16_t num_variable;
  uint16_t unka;
  uint32_t unkc;
  uint32_t library_nid;
  char* library_name;
  uint32_t* nid_vec;
  void** entry_vec;
} SceModuleExport;

static_assert(sizeof(SceModuleExport) == 0x20);

typedef struct SceModuleImport1 {
  uint16_t size;
  uint16_t version;
  uint16_t flags;
  uint16_t num_function;
  uint16_t num_variable;
  uint16_t num_tls;
  uint32_t unk_0xa;
  uint32_t library_nid;
  char* library_name;
  uint32_t unk_0x12;
  uint32_t* func_nid_vec;
  void** func_entry_vec;
  uint32_t* var_nid_vec;
  void** var_entry_vec;
  uint32_t* tls_nid_vec;
  void** tls_entry_vec;
} SceModuleImport1;

static_assert(sizeof(SceModuleImport1) == 0x34);

typedef struct SceModuleImport2 {
  uint16_t size;
  uint16_t version;
  uint16_t flags;
  uint16_t num_function;
  uint16_t num_variable;
  uint16_t unka;
  uint32_t library_nid;
  char* library_name;
  uint32_t* func_nid_vec;
  void** func_entry_vec;
  uint32_t* var_nid_vec;
  void** var_entry_vec;
} SceModuleImport2;

static_assert(sizeof(SceModuleImport2) == 0x24);

typedef struct SceModuleLibEnt {
  SceModuleLibEnt* next;
  SceModuleLibEnt* prev;
  SceModuleExport* exports;
  uint16_t syscall_info;
  uint16_t flags;
  uint32_t ClientCounter;
  void* ClientHead;
  SceUID libent_guid;
  SceUID libent_puid;
  SceModuleCB* module_cb;
  uint32_t dtrace0;
  uint32_t dtrace1;
} SceModuleLibEnt;

typedef struct SceSegmentInfoInternal {
  size_t filesz;
  size_t memsz;
  uint8_t perms[4];
  void* base_addr;
  SceUID block_id;
} SceSegmentInfoInternal;

typedef struct SceModuleSegments {
  int segmnets_num;
  SceSegmentInfoInternal segments[3];
  int meta2;
  int meta1;
} SceModuleSegments;

typedef struct SceKernelModuleSharedInfo {
  void* next;
  SceModuleCB* moduleCB;
  int ClientCounter;
  void* CachedDataSegment;
} SceKernelModuleSharedInfo;

typedef struct SceModuleCB {
  void* next;
  uint16_t flags;
  uint8_t state;
  uint8_t pad;
  uint32_t version;
  SceUID modid_kernel;
  SceUID modid_user;
  SceUID pid;
  uint16_t attr;
  uint8_t minor;
  uint8_t major;
  char* module_name;
  void* libent_top;
  void* libent_btm;
  void* libstub_top;
  void* libstub_btm;
  uint32_t fingerprint;
  void* tlsInit;
  size_t tlsInitSize;
  size_t tlsAreaSize;
  void* exidxTop;
  void* exidxBtm;
  void* extabTop;
  void* extabBtm;
  uint16_t lib_export_num;
  uint16_t lib_import_num;
  void* WorkPool;
  SceModuleExport* exports;
  void* libraries;
  void* imports;
  void* clients;
  char* path;
  SceModuleSegments segments;
  void* module_start;
  void* module_stop;
  void* module_exit;
  void* module_whatever;
  void* module_proc_param;
  void* module_start_thread_param;
  void* module_stop_thread_param;
  void* arm_exidx;
  SceKernelModuleSharedInfo* pSharedInfo;
  int unk_0xd8;
  void* probes_info;
  void* static_probes;
  int unk_e4;
  int unk_e8;
} SceModuleCB;

typedef struct SceModuleObject {
  uint32_t sce_reserved[2];
  SceModuleCB data;
} SceModuleObject;

typedef struct SceKernelLibraryDB {
  SceUID pid;
  SceModuleLibEnt* lib_ents;
  uint16_t libent_counter;
  uint16_t lost_client_counter;
  void* lost_clients;
  SceModuleCB** modules;
  uint32_t module_id;
  uint16_t module_counter;
  uint16_t flags;
  void* Addr2ModTbls;
  SceKernelSpinlock mutex;
} SceKernelLibraryDB;

typedef struct L2PageTable {
  uint8_t unk_0[0x18];
  uint32_t* pl2pte;
  uint8_t unk_32[0x24];
} L2PageTable;

typedef struct AsCommon {
  SceKernelProcessContext context;
  void* l1_pagetable;
  uint32_t* l2_pagetable_vector;
  void* l2_pagetable_vector_block;
  void* unk_18;
  void* unk_1c;
  void* unk_20;
  void* partition;
} AsCommon;

typedef struct SceAddressSpace {
  uint32_t sce_reserved[2];
  uint32_t refcount;
  uint32_t unk_c[2];
  SceUID pid;
  AsCommon* ac;
  void* partitions[0x20];
  SceUID partiton_ids[0x20];
  void* phymem_parts[0x10];
  SceUID user_iopa_uid;
  SceUID user_iotimer_uid;
  uint32_t unk_164;
  void* funcs;
  uint32_t magic;
} SceAddressSpace;

typedef struct SceUIDProcessObject {
  uint8_t unk_0[0x60];
  SceAddressSpace* as;
  uint8_t unk_96[0x47c];
} SceUIDProcessObject;

#endif
