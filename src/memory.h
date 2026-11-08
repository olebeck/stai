#pragma once

#include <stddef.h>

#include "runtime.h"

inline void* operator new(size_t size) {
    return malloc(size);
}

inline void operator delete(void* ptr) noexcept {
    free(ptr);
}

inline void operator delete(void* ptr, size_t) noexcept {
    free(ptr);
}

inline void* operator new(size_t, void* ptr) noexcept {
    return ptr;
}

inline void operator delete(void*, void*) noexcept {}
