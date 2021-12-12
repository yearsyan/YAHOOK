#pragma once
#include <cstdint>
#include <atomic>

namespace hook {

    const size_t max_alloc_len = 4096;

    class context;
    class execute_mem_pool;
    class execute_mem_pool_item {
    private:
        static const size_t unit_size = 8;
        static const size_t item_size = 4096;
        static const size_t unit_count = 512;
        void* mem_start_;
        uint64_t bit_map_[item_size/8/(sizeof(uint64_t)*8)] = {0};
        execute_mem_pool_item* next;
        execute_mem_pool_item();
        std::atomic_uint32_t write_request_;
        void* alloc_mem(size_t len);
        void free_mem(void* address, size_t len);
        void inc_write_request();
        void dec_write_request();
        bool is_this_item(void* address);
        bool has_free(int unit_index, size_t uint_need);
        friend class execute_mem_pool;
    };

    class execute_mem_pool {
    public:
        ~execute_mem_pool();
    private:
        execute_mem_pool();
        execute_mem_pool_item* head_;
        execute_mem_pool_item* tail_;
        void* alloc_mem(size_t len);
        void free_mem(void* address, size_t len);
        void code_write_done(void* address, size_t len);
        friend class context;
    };
}




