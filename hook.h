#pragma once
#include <cstdint>
#include <map>
#include <atomic>

namespace hook {


    class hook_result {
    public:
    private:
        void* trampoline_address_;
        unsigned long long trampoline_len_;
        void* origin_entry_address_;
        signed int overwrite_bytes_num_;
        void* origin_code_save_;
        friend class context;
    };

    class context {
    public:
        hook_result* hook(void* target, void* new_func);
        void unhook(void* address);
        void unhook(hook_result* res);
    private:
        std::map<void*, hook_result*> hook_map_;
        std::atomic<long> hook_lock_ = 0;
        void *alloc_code_mem(std::size_t len);
        void code_commit(void* address, std::size_t len);
        void* create_trampoline(void* back_address, void* overwrite_code, size_t overwrite_len, size_t* code_len);
        void release_code(void *address, std::size_t len);
    };

}