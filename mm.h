#pragma once
#include <cstdint>
#include <atomic>

namespace hook {

    const size_t max_alloc_len = 4096;

    class context;
    class execute_mem_pool;
    class execute_mem_pool_item {
    // 2 bytes for flags, 2 bytes for length
    private:
        static const size_t item_size = 4096;
        static const uint32_t flag_use = 0x00000001;

        void* mem_start_;
        execute_mem_pool_item* next;
        std::atomic_uint32_t write_request_;

        execute_mem_pool_item();
        void* alloc_mem(size_t len);
        void free_mem(void* address, size_t len);
        void inc_write_request();
        void dec_write_request();
        bool is_this_item(void* address);
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




