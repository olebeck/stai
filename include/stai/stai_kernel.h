#ifndef __STAI_KERNEL_H__
#define __STAI_KERNEL_H__

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write into the text memory of a process, copy on write for shared region.
 * @param[in] pid   Process to write to.
 * @param[in] addr  Destination address inside @p pid.
 * @param[in] data  Source buffer. Must be readable from kernel mode.
 * @param[in] size  Number of bytes to write.
 *
 * @return The UID of the patch on success, a negative error code otherwise.
 */
SceUID staiCowWrite(SceUID pid, uint32_t addr, const void* data, uint32_t size);

/**
 * @brief Release a patch previously returned by staiCowWrite().
 *        Pages that are no longer referenced by any write are restored.
 * @param[in] uid   UID returned by staiCowWrite().
 *
 * @return STAI_SUCCESS on success, a negative error code otherwise.
 */
int staiCowRelease(SceUID uid);

#ifdef __cplusplus
}
#endif

#endif
