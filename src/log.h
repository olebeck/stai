#pragma once

#include <psp2kern/kernel/debug.h>

#if !defined(NDEBUG) && !defined(STAI_DEBUG)
#define STAI_DEBUG
#endif

namespace stai::log {

template <typename... Args>
inline void write(const char* level, const char* format, Args... args) {
    ksceKernelPrintf("[stai:%s] ", level);
    ksceKernelPrintf(format, args...);
    ksceKernelPrintf("\n");
}

template <typename... Args>
inline void error(const char* format, Args... args) {
    write("E", format, args...);
}

template <typename... Args>
inline void info(const char* format, Args... args) {
    write("I", format, args...);
}

#ifdef STAI_DEBUG
template <typename... Args>
inline void debug(const char* format, Args... args) {
    write("D", format, args...);
}

inline void func(const char* name) {
    write("D", "%s", name);
}
#else
template <typename... Args>
inline void debug(const char*, Args...) {}

inline void func(const char*) {}
#endif

} // namespace stai::log

#define STAI_ASSERT(condition)                                                    \
    do {                                                                          \
        if(!(condition)) {                                                       \
            ::stai::log::error("assertion failed: %s (%s:%d)", #condition,        \
                               __FILE__, __LINE__);                               \
            for(;;) {                                                            \
                __asm__ volatile("" ::: "memory");                                \
            }                                                                     \
        }                                                                         \
    } while(0)

#define STAI_DEBUG_ASSERT(condition) STAI_ASSERT(condition)
#define STAI_UNUSED(value) ((void)(value))
