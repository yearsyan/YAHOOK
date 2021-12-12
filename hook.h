#pragma once
#include <cstdint>
#include <map>
#include <atomic>
#include <memory>
#include "mm.h"

#define ORIGIN_FUNCTION(save) __asm__ ("LDR %0, [x15];": "=r"(save));

namespace hook {

    class context;

    class hook_result {
    public:
        ~hook_result();
    private:
        void* trampoline_address_; // this must be at head because of ORIGIN_FUNCTION
        unsigned long long trampoline_len_;
        void* origin_entry_address_;
        signed int overwrite_bytes_num_;
        void* origin_code_save_;
        void* callee_save_trampoline_;
        unsigned long long callee_save_trampoline_len_;
        context* ctx_;
        friend class context;
    };

    class context {
    public:
        hook_result* hook(void* target, void* new_func, bool require_origin = false);
        void unhook(void* address);
        void unhook(hook_result* res);
        context();
    private:
        std::map<void*, hook_result*> hook_map_;
        std::atomic<long> hook_lock_ = 0;
        std::unique_ptr<execute_mem_pool> mem_pool_;
        void *alloc_code_mem(std::size_t len);
        void code_commit(void* address, std::size_t len);
        void* create_trampoline(void* back_address, void* overwrite_code, size_t overwrite_len, size_t* code_len);
        void* create_callee_save_trampoline(void* target_function, void* save_address, size_t* len = nullptr);
        void release_code(void *address, std::size_t len);
        friend class hook_result;
    };

}