#pragma once

#include <bits/move.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <string.h>
#include <tuple>

#include "log.h"
#include "memory.h"
#include "runtime.h"

namespace stai::cpu {

class [[nodiscard]] Syscall {
public:
    Syscall() {
        asm volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r"(state_) :: "memory");
        asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r"(state_ << 16) : "memory");
    }

    ~Syscall() {
        asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r"(state_) : "memory");
    }

    Syscall(const Syscall&) = delete;
    Syscall& operator=(const Syscall&) = delete;
    Syscall(Syscall&&) = delete;
    Syscall& operator=(Syscall&&) = delete;

private:
    u32 state_;
};

// Returns the context of @p pid, or nullptr if it could not be obtained.
inline SceKernelProcessContext* get_process_context(SceUID pid) {
    SceKernelProcessContext* context = nullptr;
    int ret = ksceKernelProcessGetContext(pid, &context);
    if(ret < 0) {
        return nullptr;
    }
    return context;
}

class [[nodiscard]] SwitchCtx {
public:
    explicit SwitchCtx(SceKernelProcessContext* context) {
        intr_ = ksceKernelCpuSuspendIntr();
        ksceKernelProcessSwitchContext(context, &previous_);
    }

    ~SwitchCtx() {
        ksceKernelProcessSwitchContext(&previous_, nullptr);
        ksceKernelCpuResumeIntr(intr_);
    }

    SwitchCtx(const SwitchCtx&) = delete;
    SwitchCtx& operator=(const SwitchCtx&) = delete;
    SwitchCtx(SwitchCtx&&) = delete;
    SwitchCtx& operator=(SwitchCtx&&) = delete;

private:
    SceKernelProcessContext previous_;
    SceKernelIntrStatus intr_;
};

template <typename T>
T copy_from_user(const T* ptr) {
    T value;
    ksceKernelCopyFromUser(&value, ptr, sizeof(T));
    return value;
}

template <typename T>
class User {
public:
    User() : ptr_(nullptr) {}
    explicit User(T* ptr) : ptr_(ptr) {}

    T* raw() const { return ptr_; }

    bool operator==(const User& other) const { return ptr_ == other.ptr_; }
    bool operator==(T* other) const { return ptr_ == other; }

    T read() const {
        T value;
        ksceKernelCopyFromUser(&value, ptr_, sizeof(T));
        return value;
    }

    void write(const T& value) const {
        ksceKernelCopyToUser(ptr_, &value, sizeof(T));
    }

private:
    T* ptr_;
};

template <typename T>
T read_user(const T* user) {
    T value;
    ksceKernelCopyFromUser(&value, user, sizeof(T));
    return value;
}

inline void write_dacr(u32 dacr) {
    asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r"(dacr));
}

inline u32 swap_dacr(u32 new_dacr) {
    u32 old_dacr;
    asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r"(old_dacr));
    asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r"(new_dacr));
    return old_dacr;
}

class [[nodiscard]] Dacr {
public:
    explicit Dacr(u32 new_dacr) {
        intr_ = ksceKernelCpuSuspendIntr();
        old_dacr_ = swap_dacr(new_dacr);
    }

    ~Dacr() {
        write_dacr(old_dacr_);
        ksceKernelCpuResumeIntr(intr_);
    }

    Dacr(const Dacr&) = delete;
    Dacr& operator=(const Dacr&) = delete;
    Dacr(Dacr&&) = delete;
    Dacr& operator=(Dacr&&) = delete;

private:
    u32 intr_;
    u32 old_dacr_;
};

inline std::tuple<u32, u32> align_cache_line(u32 vma, u32 len) {
    u32 vma_align = vma & ~0x3F;
    u32 len_align = (vma - vma_align + len + 0x3F) & ~0x3F;
    return {vma_align, len_align};
}

inline void cache_flush_kernel(u32 vma, size_t len) {
    const auto [vma_align, len_align] = align_cache_line(vma, len);
    log::debug("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);
    ksceKernelL1DcacheCleanInvalidateRange(reinterpret_cast<void*>(vma_align), len_align);
    ksceKernelIcacheInvalidateRange(reinterpret_cast<void*>(vma_align), len_align);
}

inline void cache_flush_user(u32 vma, size_t len) {
    const auto [vma_align, len_align] = align_cache_line(vma, len);
    log::debug("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);

    Dacr dacr(0x15450FC3);
    ksceKernelL1DcacheCleanInvalidateRange(reinterpret_cast<void*>(vma_align), len_align);
    ksceKernelIcacheInvalidateRange(reinterpret_cast<void*>(vma_align), len_align);
}

inline void copy_from_to_user_text_domain(void* dst, const void* src, size_t len) {
    Dacr dacr(0x15450FC3);
    // Should use user-mode ldrt/strt, but this is not critical here.
    memcpy(dst, src, len);
}

inline void copy_to_user_text_domain(void* dst, const void* src, size_t len) {
    Dacr dacr(0x15450FC3);
    // Should use user-mode ldrt/strt, but this is not critical here.
    memcpy(dst, src, len);
}

} // namespace stai::cpu
