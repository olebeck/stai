#pragma once

#include "vec.h"

namespace stai {

template <typename T, typename Key, Key T::*KeyMember>
class SortedVec : protected Vec<T> {
public:
    using Vec<T>::operator[];
    using Vec<T>::begin;
    using Vec<T>::end;
    using Vec<T>::size;
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
            bool greater = (this->data() + mid)->*KeyMember > key;
            base = greater ? base : mid;
            size -= half;
        }

        Key current = (this->data() + base)->*KeyMember;
        if(current == key) {
            return FindResult(base, true);
        }
        if(current < key) {
            base += 1;
        }
        return FindResult(base, false);
    }

    template <typename... Args>
    T* emplace_at(FindResult result, Args&&... args) {
        return Vec<T>::emplace_at(result.index(), std::forward<Args>(args)...);
    }

    template <typename... Args>
    T* emplace(Args&&... args) {
        T value(std::forward<Args>(args)...);
        FindResult result = find(value.*KeyMember);
        if(result.is_found()) {
            return nullptr;
        }
        return emplace_at(result, std::move(value));
    }

    void erase(FindResult result) {
        Vec<T>::erase(result.index());
    }

    bool erase(Key key) {
        FindResult result = find(key);
        if(!result.is_found()) {
            return false;
        }
        Vec<T>::erase(result.index());
        return true;
    }

    void erase_slice(Slice slice) {
        if(slice.ptr == nullptr) {
            return;
        }
        size_t start = slice.ptr - this->data();
        size_t end = start + slice.len;
        Vec<T>::erase_range(start, end);
    }

    Slice slice(Key start, Key end) const {
        size_t start_index = find(start).index();
        size_t end_index = find(end).index();
        if(start_index > end_index) {
            return {nullptr, 0};
        }
        return {this->data() + start_index, end_index - start_index};
    }
};

template <typename T, typename Key, Key T::*KeyMember>
class SortedDupVec : public SortedVec<T, Key, KeyMember> {
private:
    using Base = SortedVec<T, Key, KeyMember>;

public:
    using Vec<T>::operator[];
    using Vec<T>::begin;
    using Vec<T>::end;
    using Vec<T>::size;
    using Slice = typename Vec<T>::Slice;

    bool find(Key key, size_t& start, size_t& end) const {
        FindResult result = Base::find(key);
        if(!result.is_found()) {
            return false;
        }

        start = end = result.index();
        while(start > 0 && (this->data() + start - 1)->*KeyMember == key) {
            --start;
        }
        while(end < this->size() && (this->data() + end)->*KeyMember == key) {
            ++end;
        }
        return true;
    }

    template <typename... Args>
    T* emplace(Args&&... args) {
        T value(std::forward<Args>(args)...);
        FindResult result = Base::find(value.*KeyMember);
        return Base::emplace_at(result, std::move(value));
    }

    bool erase(Key key) {
        size_t start = 0;
        size_t end = 0;
        if(!find(key, start, end)) {
            return false;
        }
        Vec<T>::erase_range(start, end);
        return true;
    }

    Slice slice(Key key) const {
        size_t start = 0;
        size_t end = 0;
        if(!find(key, start, end)) {
            return Slice{nullptr, 0};
        }
        return Slice{this->data() + start, end - start};
    }
};

} // namespace stai
