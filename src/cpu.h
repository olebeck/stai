#pragma once

#include <psp2kern/kernel/cpu.h>

#include "std++.h"

struct CtxSwitched {};

class [[nodiscard]] Syscall : public CtxSwitched {
    u32 state;
    SceUID pid_;
public:
    inline_always Syscall() {
        asm volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (this->state) :: "memory");
        asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r" (this->state << 16) : "memory");
        pid_ = ksceKernelGetProcessId();
    }
    inline_always ~Syscall() {
        asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r" (state) : "memory");
    }
    Syscall(const Syscall&) = delete;
    Syscall& operator=(const Syscall&) = delete;
    Syscall(Syscall&&) = delete;

    inline_always SceUID pid() {
        return pid_;
    }
};

class [[nodiscard]] SwitchCtx : public CtxSwitched {
    SceKernelProcessContext prev_ctx;
    SceKernelIntrStatus intr;

public:
    inline_always SwitchCtx(SceUID pid) {
        SceKernelProcessContext* proc_ctx;
        ksceKernelProcessGetContext(pid, &proc_ctx);
        intr = ksceKernelCpuSuspendIntr();
        ksceKernelProcessSwitchContext(proc_ctx, &prev_ctx);
    }

    inline_always ~SwitchCtx() {
        ksceKernelProcessSwitchContext(&prev_ctx, nullptr);
        ksceKernelCpuResumeIntr(intr);
    }

    SwitchCtx(const SwitchCtx&) = delete;
    SwitchCtx& operator=(const SwitchCtx&) = delete;
    SwitchCtx(SwitchCtx&&) = delete;
};

class [[nodiscard]] SuspendIntr {
    SceKernelIntrStatus intr;
public:
    inline_always SuspendIntr() {
        intr = ksceKernelCpuSuspendIntr();
    }
    inline_always ~SuspendIntr() {
        ksceKernelCpuResumeIntr(intr);
    }
};

template<typename T>
T inline_always copy_from_user(CtxSwitched&, T* ptr) {
    T value;
    ksceKernelCopyFromUser(&value, ptr, sizeof(T));
    return std::move(value);
}

template<typename T>
class User {
private:
    T* ptr;
public:
    inline_always User() : ptr(nullptr) {}
    inline_always User(T* ptr) : ptr(ptr) {}

    inline_always T* raw() {
        return ptr;
    }

    inline_always bool operator==(User<T>& other) {
        return this->ptr == other.ptr;
    }

    inline_always bool operator==(T* other) {
        return this->ptr == other;
    }

    inline_always T read(CtxSwitched&) {
        T value; 
        ksceKernelCopyFromUser(&value, this->ptr, sizeof(T));
        return value;
    }

    inline_always void write(CtxSwitched& sw, T&& value) {
        this->write(sw, value);
    }

    inline_always void write(CtxSwitched& sw, T& value) {
        ksceKernelCopyToUser(this->ptr, &value, sizeof(T));
    }
};

template<typename T>
T read_user(CtxSwitched& sw, const T* user) {
    T value;
    ksceKernelCopyFromUser(&value, user, sizeof(T));
    return value;
}

static inline_always void write_dacr(u32 dacr) {
    asm volatile("mcr p15, 0, %0, c3, c0, 0" ::"r"(dacr));
}

static inline_always u32 swap_dacr(u32 new_dacr) {
    u32 old_dacr;
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(old_dacr));
    asm volatile("mcr p15, 0, %0, c3, c0, 0" ::"r"(new_dacr));
    return old_dacr;
}

class [[nodiscard]] Dacr {
    u32 old_dacr;
public:
    inline_always Dacr(u32 new_dacr) {
        old_dacr = swap_dacr(new_dacr);
    }
    inline_always ~Dacr() {
        write_dacr(old_dacr);
    }
    Dacr(const Dacr&) = delete;
    Dacr& operator=(const Dacr&) = delete;
    Dacr(Dacr&&) = delete;
};

std::tuple<u32, u32> inline_always align_cache_line(u32 vma, u32 len) {
    u32 vma_align = vma & ~0x3F;
    u32 len_align = ((vma - vma_align + len + 0x3F) & ~0x3F);
    return {vma_align, len_align};
}

void inline_always cache_flush_kernel(u32 vma, size_t len) {
    const auto [vma_align, len_align] = align_cache_line(vma, len);
    LOGD("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);
    ksceKernelL1DcacheCleanInvalidateRange((void*)vma_align, len_align);
    ksceKernelIcacheInvalidateRange((void*)vma_align, len_align);
};

void inline_always cache_flush_user(CtxSwitched&, u32 vma, size_t len) {
    const auto [vma_align, len_align] = align_cache_line(vma, len);
    LOGD("vma %p, vma_align %p, len 0x%x", vma, vma_align, len_align);

    Dacr dacr(0x15450FC3);
    ksceKernelL1DcacheCleanInvalidateRange((void*)vma_align, len_align);
    ksceKernelIcacheInvalidateRange((void*)vma_align, len_align);
}

void inline_always copy_from_to_user_text_domain(CtxSwitched&, void* dst, void* src, size_t len) {
    Dacr dacr(0x15450FC3);
    // should usr ldrt and strt but thats not *that* important
    memcpy(dst, src, len); 
}

void inline_always copy_to_user_text_domain(CtxSwitched&, void* dst, void* src, size_t len) {
    Dacr dacr(0x15450FC3);
    // should usr ldrt and strt but thats not *that* important
    memcpy(dst, src, len);
}
