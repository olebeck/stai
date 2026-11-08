#pragma once

#include <psp2kern/types.h>
#include <psp2kern/kernel/threadmgr.h>

namespace stai {

class [[nodiscard]] ScopeLock {
public:
    explicit ScopeLock(SceUID mutex) : mutex_(mutex) {
        ksceKernelLockMutex(mutex_, 1, nullptr);
    }

    ~ScopeLock() {
        ksceKernelUnlockMutex(mutex_, 1);
    }

    ScopeLock(const ScopeLock&) = delete;
    ScopeLock& operator=(const ScopeLock&) = delete;
    ScopeLock(ScopeLock&&) = delete;
    ScopeLock& operator=(ScopeLock&&) = delete;

private:
    SceUID mutex_;
};

} // namespace stai
