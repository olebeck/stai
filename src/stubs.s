.macro vitastub lib, name, flags, libnid, funcnid
  .arm
  .arch armv7a
  .section .vitalink.fstubs.\lib,"ax"
  .align 4
  .global \name
  .type \name, %function
  \name:
    .word \flags
    .word \libnid
    .word \funcnid
    .align 4
.endm

.macro vitastub_ver lib, name, flags, libnid_360, funcnid_360, libnid_363, funcnid_363
  vitastub \lib \name\()_360 \flags \libnid_360 \funcnid_360
  vitastub \lib \name\()_363 \flags \libnid_363 \funcnid_363

  .section .data.fstubs,"aw"
  .align 4
  .global \name\()_stub
  .type \name\()_stub, %object
  \name\()_stub:
    .word \name\()_360

  .section .text,"ax"
  .global \name
  .type \name, %function
  \name:
    ldr r12, 1f
    ldr r12, [r12]
    bx  r12
  .align 2
  1: .word \name\()_stub
.endm

.macro patch_363 name
  ldr r2, =\name\()_stub
  ldr r1, =\name\()_363
  str r1, [r2]
.endm

vitastub_ver SceCpuForKernel, ksceKernelIcacheInvalidateRange, 0x18, 0x54BF2BAB, 0x19F17BD0, 0xA5195D20, 0x73E895EA
vitastub_ver SceCpuForKernel, ksceKernelL1DcacheCleanInvalidateRange, 0x18, 0x54BF2BAB, 0x6BA2E51C, 0xA5195D20, 0x4F442396
vitastub_ver SceSysmemForKernel, ksceKernelCopyToUserTextDomain, 0x18, 0x63A519E5, 0x67BAD5B4, 0x02451F0F, 0x5EF1DAAF
vitastub_ver SceSysmemForKernel, ksceKernelFindClassByName, 0x18, 0x63A519E5, 0x62989905, 0x02451F0F, 0x7D87F706
vitastub_ver SceSysmemForKernel, ksceKernelReallocHeapMemory, 0x18, 0x02451F0F, 0x8EE8B917, 0x63A519E5, 0xFDC0EA11
vitastub_ver SceProcessmgrForKernel, ksceKernelGetProcessModuleInfo, 0x18, 0x7A69DE86, 0xC1C91BB2, 0xEB1F8EF7, 0x3AF6B088
vitastub_ver SceModulemgrForKernel, ksceKernelGetModuleCB, 0x18, 0xC445FA63, 0xFE303863, 0x92C9FFC2, 0x37512E29

// ksceKernelPrintf but renamed for substitute
vitastub SceDebugForDriver, printf, 0x10, 0x88758561, 0x391b74b7

.section .text,"ax"
.global init_363_stubs
.type init_363_stubs, %function
init_363_stubs:
  patch_363 ksceKernelIcacheInvalidateRange
  patch_363 ksceKernelL1DcacheCleanInvalidateRange
  patch_363 ksceKernelCopyToUserTextDomain
  patch_363 ksceKernelFindClassByName
  patch_363 ksceKernelReallocHeapMemory
  patch_363 ksceKernelGetProcessModuleInfo
  patch_363 ksceKernelGetModuleCB
  bx lr
