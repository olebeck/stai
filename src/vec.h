#pragma once

#include <bits/move.h>
#include <stddef.h>

#include "memory.h"
#include "runtime.h"

namespace stai {

// Negative result means "not found"; the low bits are the insert index.
struct FindResult {
    u32 value;

    constexpr FindResult(size_t index, bool found)
        : value(static_cast<u32>(index) | (found ? 0u : 0x80000000u)) {}

    constexpr bool is_found() const { return (value & 0x80000000u) == 0; }
    constexpr size_t index() const { return value & ~0x80000000u; }
};

template <typename T>
class Vec {
public:
    Vec() = default;

    explicit Vec(size_t capacity) {
        reserve(capacity);
    }

    Vec(Vec&& other) : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
        other.data_ = nullptr;
        other.size_ = other.capacity_ = 0;
    }

    Vec& operator=(Vec&& other) {
        if(this != &other) {
            destroy_all();
            free(data_);
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.data_ = nullptr;
            other.size_ = other.capacity_ = 0;
        }
        return *this;
    }

    Vec(const Vec&) = delete;
    Vec& operator=(const Vec&) = delete;

    ~Vec() {
        destroy_all();
        free(data_);
        data_ = nullptr;
    }

    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }
    bool empty() const { return size_ == 0; }
    T* data() const { return data_; }

    bool reserve(size_t new_capacity) {
        if(new_capacity <= capacity_) {
            return true;
        }
        return grow_to(new_capacity);
    }

    bool shrink_to_fit() {
        if(size_ == capacity_) {
            return true;
        }
        if(size_ == 0) {
            free(data_);
            data_ = nullptr;
            capacity_ = 0;
            return true;
        }
        void* ptr = realloc(data_, size_ * sizeof(T));
        if(ptr == nullptr) {
            return false;
        }
        data_ = static_cast<T*>(ptr);
        capacity_ = size_;
        return true;
    }

    struct Iterator {
        using value_type = T;
        using difference_type = ptrdiff_t;
        using pointer = T*;
        using reference = T&;

        explicit Iterator(T* ptr) : ptr_(ptr) {}

        T& operator*() const { return *ptr_; }
        T* operator->() const { return ptr_; }
        T& operator[](ptrdiff_t index) const { return ptr_[index]; }

        Iterator& operator++() {
            ++ptr_;
            return *this;
        }

        Iterator operator++(int) {
            Iterator copy = *this;
            ++ptr_;
            return copy;
        }

        Iterator& operator--() {
            --ptr_;
            return *this;
        }

        Iterator operator--(int) {
            Iterator copy = *this;
            --ptr_;
            return copy;
        }

        Iterator& operator+=(ptrdiff_t count) {
            ptr_ += count;
            return *this;
        }

        Iterator& operator-=(ptrdiff_t count) {
            ptr_ -= count;
            return *this;
        }

        friend Iterator operator+(Iterator it, ptrdiff_t count) { return it += count; }
        friend Iterator operator+(ptrdiff_t count, Iterator it) { return it += count; }
        friend Iterator operator-(Iterator it, ptrdiff_t count) { return it -= count; }
        friend ptrdiff_t operator-(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ - rhs.ptr_; }

        friend bool operator==(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ == rhs.ptr_; }
        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ != rhs.ptr_; }
        friend bool operator<(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ < rhs.ptr_; }
        friend bool operator>(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ > rhs.ptr_; }
        friend bool operator<=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ <= rhs.ptr_; }
        friend bool operator>=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr_ >= rhs.ptr_; }

        T* raw() const { return ptr_; }

    private:
        T* ptr_;
    };

    Iterator begin() { return Iterator(data_); }
    Iterator end() { return Iterator(data_ + size_); }
    Iterator begin() const { return Iterator(data_); }
    Iterator end() const { return Iterator(data_ + size_); }

    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }

    T* front() const { return size_ ? data_ : nullptr; }
    T* back() const { return size_ ? data_ + size_ - 1 : nullptr; }

    T* push_back(T&& value) {
        if(size_ == capacity_ && !grow()) {
            return nullptr;
        }
        T* slot = data_ + size_++;
        new (slot) T(std::move(value));
        return slot;
    }

    template <typename... Args>
    T* emplace_back(Args&&... args) {
        if(size_ == capacity_ && !grow()) {
            return nullptr;
        }
        T* slot = data_ + size_++;
        new (slot) T(std::forward<Args>(args)...);
        return slot;
    }

    T* insert(size_t index, T&& value) {
        if(index > size_ || (size_ == capacity_ && !grow())) {
            return nullptr;
        }
        shift_right(index, 1);
        T* slot = data_ + index;
        new (slot) T(std::move(value));
        size_++;
        return slot;
    }

    template <typename... Args>
    T* emplace_at(size_t index, Args&&... args) {
        if(index > size_ || (size_ == capacity_ && !grow())) {
            return nullptr;
        }
        shift_right(index, 1);
        T* slot = data_ + index;
        new (slot) T(std::forward<Args>(args)...);
        size_++;
        return slot;
    }

    void erase(size_t index) {
        if(index >= size_) {
            return;
        }
        data_[index].~T();
        shift_left(index + 1, 1);
        size_--;
    }

    void erase_range(size_t start, size_t end) {
        if(start >= end || start >= size_) {
            return;
        }
        if(end > size_) {
            end = size_;
        }
        size_t count = end - start;
        for (size_t i = start; i < end; i++) {
            data_[i].~T();
        }
        shift_left(end, count);
        size_ -= count;
    }

    void clear() {
        destroy_all();
        size_ = 0;
    }

    struct Slice {
        T* ptr;
        size_t len;

        T& operator[](size_t index) { return ptr[index]; }
        T* begin() { return ptr; }
        T* end() { return ptr + len; }
    };

    Slice slice(size_t start, size_t len) const {
        if(start >= size_) {
            return {nullptr, 0};
        }
        if(start + len > size_) {
            len = size_ - start;
        }
        return {data_ + start, len};
    }

private:
    void destroy_all() {
        for (size_t i = 0; i < size_; i++) {
            data_[i].~T();
        }
    }

    bool grow() {
        return grow_to(capacity_ ? capacity_ * 2 : 4);
    }

    bool grow_to(size_t new_capacity) {
        T* ptr = static_cast<T*>(malloc(new_capacity * sizeof(T)));
        if(ptr == nullptr) {
            return false;
        }
        for (size_t i = 0; i < size_; i++) {
            new (ptr + i) T(std::move(data_[i]));
            // data_[i] is intentionally left undestroyed after being moved from.
        }
        free(data_);
        data_ = ptr;
        capacity_ = new_capacity;
        return true;
    }

    void shift_right(size_t offset, size_t count) {
        for (size_t i = size_; i > offset; --i) {
            size_t src = i - 1;
            size_t dst = src + count;
            new (data_ + dst) T(std::move(data_[src]));
            // data_[src] is intentionally left undestroyed after being moved from.
        }
    }

    void shift_left(size_t offset, size_t count) {
        for (size_t i = offset; i < size_; i++) {
            new (data_ + i - count) T(std::move(data_[i]));
            // data_[i] is intentionally left undestroyed after being moved from.
        }
    }

    T* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

} // namespace stai
