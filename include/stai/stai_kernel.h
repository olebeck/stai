#ifndef __STAI_KERNEL_H__
#define __STAI_KERNEL_H__

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write into the text memory of a process, copy on write for shared region.
 * @param[in] pid   Process to write to.
 * @param[in] dst   Destination address inside @p pid.
 * @param[in] data  Source buffer. Must be readable from kernel mode.
 * @param[in] len   Number of bytes to write.
 *
 * @return STAI_SUCCESS on success, a negative error code otherwise.
 */
int staiWriteText(SceUID pid, uint32_t dst, const void* data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
