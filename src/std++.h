#pragma once

#include "std.h"
#include <psp2kern/kernel/sysmem.h>

#include <bits/move.h>

#define always_inline __attribute__((always_inline)) inline

class CtxSwitched {};

void cache_flush_kernel(u32 ptr, size_t len);
void cache_flush_user(CtxSwitched sw, u32 vma, size_t len);

template<typename T>
class User {
private:
  T* ptr;
public:
  always_inline User() : ptr(nullptr) {}
  always_inline User(T* ptr) : ptr(ptr) {}

  always_inline bool operator==(User<T>& other) {
    return this->ptr == other.ptr;
  }

  always_inline bool operator==(void* other) {
    return this->ptr == other;
  }

  always_inline T read(CtxSwitched) {
    T value; 
    ksceKernelCopyFromUser(&value, this->ptr, sizeof(T));
    return value;
  }

  always_inline void write(CtxSwitched sw, T&& value) {
    this->write(sw, value);
  }

  always_inline void write(CtxSwitched sw, T& value) {
    ksceKernelCopyToUser(this->ptr, &value, sizeof(T));
    cache_flush_user(sw, (u32)this->ptr, sizeof(T));
  }
};

template<typename T>
T read_user(CtxSwitched sw, const T* user) {
  T value;
  ksceKernelCopyFromUser(&value, user, sizeof(T));
  return value;
}

class SyscallState {
  u32 state;
public:
  always_inline SyscallState(u32 state) : state(state) {}
  always_inline ~SyscallState() {
    asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r" (state) : "memory");
  }
  SyscallState(const SyscallState&) = delete;
  SyscallState& operator=(const SyscallState&) = delete;

  always_inline CtxSwitched sw() {
    return CtxSwitched{};
  }
};

always_inline SyscallState enter_syscall() {
  u32 state;
  asm volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (state));
  asm volatile ("mcr p15, 0, %0, c13, c0, 3" :: "r" (state << 16) : "memory");
  return SyscallState(state);
}

struct ProcessCtx {
  SceKernelProcessContext prev_ctx;
  SceKernelIntrStatus intr;

  always_inline ~ProcessCtx() {
    ksceKernelProcessSwitchContext(&prev_ctx, nullptr);
    ksceKernelCpuResumeIntr(intr);
  }

  CtxSwitched sw() {
    return CtxSwitched{};
  }
};

always_inline ProcessCtx switch_ctx(SceUID pid) {
  SceKernelProcessContext prev_ctx;
  SceKernelProcessContext* proc_ctx;
  ksceKernelProcessGetContext(pid, &proc_ctx);
  SceKernelIntrStatus intr = ksceKernelCpuSuspendIntr();
  ksceKernelProcessSwitchContext(proc_ctx, &prev_ctx);
  return ProcessCtx{prev_ctx, intr};
}

always_inline void restore_ctx(ProcessCtx&& ctx) { /* calls destructor */ }

class ScopeLock {
  SceUID mutex;
public:
  always_inline ScopeLock(SceUID mutex) : mutex(mutex) {
    ksceKernelLockMutex(mutex, 1, NULL);
  }
  always_inline ~ScopeLock() {
    ksceKernelUnlockMutex(mutex, 1);
  }
};

always_inline void* operator new(size_t size) {
  return malloc(size);
};
always_inline void operator delete(void* ptr) {
  free(ptr);
};

always_inline void* operator new(size_t size, void* ptr) {
  return ptr;
}

always_inline void operator delete(void* ptr, void*) {
  operator delete(ptr);
}

template<typename T>
class Vec {
private:
  T* m_data = nullptr;
  size_t m_size = 0;
  size_t m_cap = 0;

public:
  Vec() = default;
  explicit Vec(size_t cap) {
    reserve(cap);
  }

  Vec(Vec&& o) : m_data(o.m_data), m_size(o.m_size), m_cap(o.m_cap)
    { o.m_data = nullptr; o.m_size = o.m_cap = 0; }

  Vec& operator=(Vec&& o) {
    if (this != &o) {
      destroy_all();
      free(m_data);
      m_data = o.m_data; m_size = o.m_size; m_cap = o.m_cap;
      o.m_data = nullptr; o.m_size = o.m_cap = 0;
    }
    return *this;
  }

  Vec(const Vec&) = delete;
  Vec& operator=(const Vec&) = delete;

  ~Vec() {
    destroy_all();
    free(m_data);
    m_data = nullptr;
  }

  size_t size()     const { return m_size; }
  size_t capacity() const { return m_cap;  }
  bool   empty()    const { return m_size == 0; }
  T*     data()     const { return m_data; }

  bool reserve(size_t new_cap) {
    if (new_cap <= m_cap) return true;
    return grow_to(new_cap);
  }

  bool shrink_to_fit() {
    if (m_size == m_cap) return true;
    if (m_size == 0) {
      free(m_data);
      m_data = nullptr;
      m_cap = 0;
      return true;
    }
    void* p = realloc(m_data, m_size * sizeof(T));
    if (!p) {
      return false;
    }
    m_data = static_cast<T*>(p);
    m_cap  = m_size;
    return true;
  }

  struct iterator {
    using value_type        = T;
    using difference_type   = ptrdiff_t;
    using pointer           = T*;
    using reference         = T&;

    explicit iterator(T* p) : ptr(p) {}

    T& operator*()  const { return *ptr; }
    T* operator->() const { return ptr; }
    T& operator[](ptrdiff_t n) const { return ptr[n]; }

    iterator& operator++()    { ++ptr; return *this; }
    iterator  operator++(int) { iterator t=*this; ++ptr; return t; }
    iterator& operator--()    { --ptr; return *this; }
    iterator  operator--(int) { iterator t=*this; --ptr; return t; }

    iterator& operator+=(ptrdiff_t n) { ptr += n; return *this; }
    iterator& operator-=(ptrdiff_t n) { ptr -= n; return *this; }

    friend iterator  operator+(iterator it, ptrdiff_t n)          { it += n; return it; }
    friend iterator  operator+(ptrdiff_t n, iterator it)          { it += n; return it; }
    friend iterator  operator-(iterator it, ptrdiff_t n)          { it -= n; return it; }
    friend ptrdiff_t operator-(const iterator& a, const iterator& b) { return a.ptr - b.ptr; }

    friend bool operator==(const iterator& a, const iterator& b) { return a.ptr == b.ptr; }
    friend bool operator!=(const iterator& a, const iterator& b) { return a.ptr != b.ptr; }
    friend bool operator< (const iterator& a, const iterator& b) { return a.ptr <  b.ptr; }
    friend bool operator> (const iterator& a, const iterator& b) { return a.ptr >  b.ptr; }
    friend bool operator<=(const iterator& a, const iterator& b) { return a.ptr <= b.ptr; }
    friend bool operator>=(const iterator& a, const iterator& b) { return a.ptr >= b.ptr; }

    T* raw() const { return ptr; }
  private:
    T* ptr;
  };

  iterator begin() { return iterator(m_data); }
  iterator end()   { return iterator(m_data + m_size); }
  const iterator begin() const { return iterator(m_data); }
  const iterator end()   const { return iterator(m_data + m_size); }

  T& operator[](size_t i)       { return m_data[i]; }
  const T& operator[](size_t i) const { return m_data[i]; }

  T* front() const { return m_size ? m_data : nullptr; }
  T* back()  const { return m_size ? m_data + m_size - 1 : nullptr; }

  T* push_back(T&& value) {
    if (m_size == m_cap && !grow()) return nullptr;
    T* slot = m_data + m_size++;
    new(slot) T(std::move(value));
    return slot;
  }

  template<typename... Args>
  T* emplace_back(Args&&... args) {
    if (m_size == m_cap && !grow()) return nullptr;
    T* slot = m_data + m_size++;
    new(slot) T(std::forward<Args>(args)...);
    return slot;
  }

  T* insert(size_t index, T&& value) {
    if (index > m_size) return nullptr;
    if (m_size == m_cap && !grow()) return nullptr;
    shift_right(index, 1);
    T* slot = m_data + index;
    new(slot) T(std::move(value));
    m_size++;
    return slot;
  }

  template<typename... Args>
  T* emplace_at(size_t index, Args&&... args) {
    if (index > m_size) return nullptr;
    if (m_size == m_cap && !grow()) return nullptr;
    shift_right(index, 1);
    T* slot = m_data + index;
    new(slot) T(std::forward<Args>(args)...);
    m_size++;
    return slot;
  }

  void erase(size_t index) {
    if (index >= m_size) return;
    m_data[index].~T();
    shift_left(index + 1, 1);
    m_size--;
  }

  void erase_range(size_t start, size_t end) {
    if (start >= end || start >= m_size) return;
    if (end > m_size) end = m_size;
    size_t count = end - start;
    for (size_t i = start; i < end; i++) m_data[i].~T();
    shift_left(end, count);
    m_size -= count;
  }

  void clear() {
    destroy_all();
    m_size = 0;
  }

  struct Slice {
    T*     ptr;
    size_t len;
    T& operator[](size_t i) { return ptr[i]; }
    T* begin() { return ptr; }
    T* end()   { return ptr + len; }
  };

  Slice slice(size_t start, size_t len) const {
    if (start >= m_size) return {nullptr, 0};
    if (start + len > m_size) len = m_size - start;
    return {m_data + start, len};
  }
private:
  void destroy_all() {
    for (size_t i = 0; i < m_size; i++) {
      m_data[i].~T();
    }
  }

  bool grow() {
    return grow_to(m_cap ? m_cap * 2 : 4);
  }

  bool grow_to(size_t new_cap) {
    T* p = (T*)malloc(new_cap * sizeof(T));
    if (!p) return false;
    for (size_t i = 0; i < m_size; i++) {
      new(p + i) T(std::move(m_data[i]));
      // m_data[i].~T(); // intentionally not destructing since its moved
    }
    free(m_data);
    m_data = p;
    m_cap  = new_cap;
    return true;
  }

  void shift_right(size_t offset, size_t count) {
    for (size_t i = m_size; i > offset; --i) {
      size_t src = i - 1;
      size_t dst = src + count;
      new(m_data + dst) T(std::move(m_data[src]));
      // m_data[src].~T(); // intentionally not destructing since its moved
    }
  }

  void shift_left(size_t offset, size_t count) {
    for (size_t i = offset; i < m_size; i++) {
      new(m_data + i - count) T(std::move(m_data[i]));
      // m_data[i].~T(); // intentionally not destructing since its moved
    }
  }
};

// negative = not found, -value = insert index
struct FindResult {
  u32 value;
  FindResult(u32 index, bool found) : value(index | (found ? 0 : 0x80000000)) {}
  bool is_found() { return (value & 0x80000000) == 0; }
  size_t index() { return value & ~0x80000000; }
};

template<typename T, typename Key, Key T::* KeyElem>
class SortedVec : protected Vec<T> {
public:
  using Vec<T>::operator[];
  using Vec<T>::begin;
  using Vec<T>::end;
  using Slice = typename Vec<T>::Slice;

  FindResult find(Key key) const {
    size_t size = this->size();
    if(size == 0) {
      return FindResult(0, false);
    }
    size_t base = 0;
    while(size > 1) {
      size_t half = size / 2;
      size_t mid = base + half;
      bool greater = (this->data() + mid)->*KeyElem > key;
      base = greater ? base : mid;
      size -= half;
    }
    Key key2 = (this->data() + base)->*KeyElem;
    if(key2 == key) {
      return FindResult(base, true);
    } else if(key2 < key) {
      base += 1;
    }
    return FindResult(base, false);
  }

  template<typename... Args>
  T* emplace_at(FindResult find, Args&&... args) {
    return Vec<T>::emplace_at(find.index(), std::forward<Args>(args)...);
  }

  template<typename... Args>
  T* emplace(Args&& ... args) {
    T temp(std::forward<decltype(args)>(args)...);
    FindResult result = this->find(temp.*KeyElem);
    if(result.is_found()) {
      return nullptr;
    }
    return emplace_at(result, std::move(temp));
  }

  void erase(FindResult result) {
    Vec<T>::erase(result.index());
  }

  bool erase(Key key) {
    auto result = this->find(key);
    if(result.is_found()) {
      Vec<T>::erase(result.index());
      return true;
    }
    return false;
  }

  void erase_slice(Slice&& slice) {
    if(slice.ptr == nullptr) return;
    size_t start = slice.ptr - this->data();
    size_t end = start + slice.len;
    Vec<T>::erase_range(start, end);
  }
  
  Slice slice(Key start, Key end) const {
    FindResult start_result = this->find(start);
    FindResult end_result = this->find(end);
    size_t start_index = start_result.index();
    size_t end_index = end_result.index();
    if(start_index > end_index) {
      return {nullptr, 0};
    }
    return {this->data() + start_index, end_index - start_index};
  }
};

template<typename T, typename Key, Key T::* KeyElem>
class SortedDupVec : SortedVec<T, Key, KeyElem> {
private:
  using super = SortedVec<T, Key, KeyElem>;
public:
  using Vec<T>::operator[];
  using Vec<T>::begin;
  using Vec<T>::end;
  using Slice = typename Vec<T>::Slice;

  bool find(Key key, size_t& start, size_t& end) const {
    auto result = super::find(key);
    if(!result.is_found()) {
      return false;
    }
    start = end = result.index();
    while(start > 0 && (this->data() + start - 1)->*KeyElem == key) {
      --start;
    }
    while(end < this->size() && (this->data() + end)->*KeyElem == key) {
      ++end;
    }
    return true;
  }

  template<typename... Args>
  T* emplace(Args&& ... args) {
    T temp(std::forward<decltype(args)>(args)...);
    FindResult result = super::find(temp.*KeyElem);
    return super::emplace_at(result, std::move(temp));
  }

  bool erase(Key key) {
    size_t start, end;
    if(!this->find(key, start, end)) {
      return false;
    }
    Vec<T>::erase_range(start, end);
    return true;
  }

  Slice slice(Key key) const {
    size_t start, end;
    if(!this->find(key, start, end)) {
      return Slice{nullptr, 0};
    }
    return Slice{this->data() + start, end - start};
  }
};
