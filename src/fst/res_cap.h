#pragma once
#include "fst/dlut.h"

namespace pfm
{
    template<std::derived_from<struct FD4ResCap> ResCap>
    struct ResRepository;

    /// Class which encapsulates a file resource. 
    struct FD4ResCap {
        void** vtable;
        FD4ResHashString resource_name;
        ResRepository<FD4ResCap>* owner;
        FD4ResCap* next;
        uint32_t ref_count;
        uint32_t pad_5c;
    };

    /// Encapsulates a param file. No RTTI name, so not sure if this is really a FileCap.
    struct ParamFileCap : public FD4ResCap {
        uint8_t unk_00[0x18];
        size_t param_file_size;
        struct ParamFile* param_file;
    };

    /// FD4ResCap struct which encapsulates a param file container. 
    struct ParamResCap : public FD4ResCap {
        uint8_t unk_00[0x20];
        ParamFileCap* param_file_cap;
    };

    template<std::derived_from<FD4ResCap> ResCap>
    struct ResRepository {
        void** vtable;
        void* allocator;
        void* owning_repository;
        uint32_t unk_18;
        uint32_t capacity;
        ResCap** buckets;

        struct Iterator 
        {
            using iterator_category = std::forward_iterator_tag;
            using difference_type   = std::ptrdiff_t;
            using value_type        = ResCap;
            using pointer           = ResCap*;
            using reference         = ResCap&;

            reference operator*() const { return *rescap; }
            pointer operator->() const { return rescap; }
            
            Iterator& operator++() {
                if (bucket == past_end_bucket) 
                    return *this;
                
                rescap = (ResCap*)rescap->next;
                while (!rescap && ++bucket < past_end_bucket)
                    rescap = *bucket;

                return *this;
            }

            Iterator operator++(int) { Iterator tmp = *this; ++(*this); return tmp; }
            
            friend bool operator== (const Iterator& a, const Iterator& b) { return a.rescap == b.rescap; };
            friend bool operator!= (const Iterator& a, const Iterator& b) { return a.rescap != b.rescap; }; 

            Iterator() = default;
        private:
            friend struct ResRepository;

            Iterator(ResCap* rescap, ResCap** bucket, ResCap** past_end_bucket) :
                rescap(rescap), bucket(bucket), past_end_bucket(past_end_bucket) {};

            ResCap* rescap = nullptr;
            ResCap** bucket = nullptr;
            ResCap** past_end_bucket = nullptr;
        };

        Iterator begin() const {
            Iterator it { nullptr, buckets, buckets + capacity };
            // Skip to first non-empty bucket
            while (!it.rescap && ++it.bucket < it.past_end_bucket)
                it.rescap = *it.bucket;
            
            return it;
        }

        Iterator end() const {
            return { nullptr, buckets + capacity, buckets + capacity };
        }
    };
}