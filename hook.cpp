#include "hook.h"

#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cstring>

#define PAGE_ADDRESS_OF(x) (reinterpret_cast<int64_t>(x) & 0xfffffffffffff000)
#define PAGE_SIZE (1024*4)
#define LOOP_INS ((uint32_t)0x14000000);
#define AARCH64_INS_LEN (4)

namespace hook {

    long get_pid() {
        return syscall(__NR_gettid);
    }

    int enable_page_write(void* address, size_t len) {
        auto page_align_address = (void*)PAGE_ADDRESS_OF(address);
        auto page_align_end_address = (void*)PAGE_ADDRESS_OF((char *)address + len);
        size_t page_align_size = ((size_t)page_align_end_address - (size_t)page_align_address) + PAGE_SIZE;
        return mprotect(page_align_address, page_align_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    int disable_page_write(void* address, size_t len) {
        auto page_align_address = (void*)PAGE_ADDRESS_OF(address);
        auto page_align_end_address = (void*)PAGE_ADDRESS_OF((char *)address + len);
        size_t page_align_size = ((size_t)page_align_end_address - (size_t)page_align_address) + PAGE_SIZE;
        return mprotect(page_align_address, page_align_size, PROT_READ | PROT_EXEC);
    }

    hook_result::~hook_result() {
        if (origin_code_save_ != nullptr) {
            delete[] reinterpret_cast<char *>(origin_code_save_);
        }
        if (trampoline_address_ != nullptr) {
            ctx_->release_code(trampoline_address_, trampoline_len_);
        }
        if (callee_save_trampoline_ != nullptr) {
            ctx_->release_code(callee_save_trampoline_, callee_save_trampoline_len_);
        }
    }


    void* context::create_trampoline(void* back_address, void* overwrite_code, size_t overwrite_len, size_t* code_len) {
        auto code_mem = alloc_code_mem(overwrite_len + 4*AARCH64_INS_LEN);
        const unsigned char back_code[] = {
                0x50, 0x00, 0x00, 0x58, //ldr x16, #8
                0x00, 0x02, 0x1f, 0xd6 // br x16
        };
        memcpy(code_mem, overwrite_code, overwrite_len);
        memcpy(reinterpret_cast<char *>(code_mem) + overwrite_len, back_code, sizeof(back_code));
        memcpy(reinterpret_cast<char *>(code_mem) + overwrite_len + sizeof(back_code), &back_address, sizeof(void*));
        code_commit(code_mem, overwrite_len + 4*AARCH64_INS_LEN);

        if (code_len != nullptr) {
            *code_len = overwrite_len + 4*AARCH64_INS_LEN;
        }

        return code_mem;
    }

    void* context::create_callee_save_trampoline(void* target_function, void* save_address, size_t* len) {
        auto code_mem =  reinterpret_cast<char*>(alloc_code_mem(2 * sizeof(void*) + 3 * AARCH64_INS_LEN));
        const unsigned char code[] = {
                0x6f, 0x00, 0x00, 0x58, //ldr x15, #12
                0x90, 0x00, 0x00, 0x58, //ldr x16, #16
                0x00, 0x02, 0x1f, 0xd6 // br x16
        };
        memcpy(code_mem, code, sizeof(code));
        memcpy(code_mem + sizeof(code), &save_address, sizeof(save_address));
        memcpy(code_mem + sizeof(code) + sizeof(save_address), &target_function, sizeof(target_function));
        code_commit(code_mem, 2 * sizeof(void*) + 3 * AARCH64_INS_LEN);

        if (len != nullptr) {
            *len = 2* sizeof(void*) + 3 * AARCH64_INS_LEN;
        }

        return code_mem;
    }


    context::context(): mem_pool_(std::unique_ptr<execute_mem_pool>(new execute_mem_pool)) {}

    void *context::alloc_code_mem(std::size_t len) {
        return mem_pool_->alloc_mem(len);
    }

    void context::code_commit(void *address, size_t len) {
        mem_pool_->code_write_done(address, len);
    }

    void context::release_code(void *address, std::size_t len) {
        mem_pool_->free_mem(address, len);
    }

    void context::unhook(void *address) {
        unhook(hook_map_[address]);
    }

    void context::unhook(hook_result *res) {
        if (res == nullptr) {
            return;
        }

        auto pid = get_pid();
        while (true) {
            while (hook_lock_.load() != 0); // wait
            hook_lock_.store(pid);
            if (hook_lock_.load() == pid) {
                break;
            }
        }

        enable_page_write(res->origin_entry_address_, res->overwrite_bytes_num_);
        auto target_ins_ptr = reinterpret_cast<uint32_t*>(res->origin_entry_address_);
        auto origin_save_ptr = reinterpret_cast<uint32_t*>(res->origin_code_save_);
        target_ins_ptr[0] = LOOP_INS;

        
        memcpy(target_ins_ptr + 1, origin_save_ptr + 1, res->overwrite_bytes_num_ - AARCH64_INS_LEN);
        target_ins_ptr[0] = origin_save_ptr[0];
        disable_page_write(res->origin_entry_address_, res->overwrite_bytes_num_);
        hook_map_.erase(res->origin_entry_address_);
        delete res;

        hook_lock_.store(0);
    }

    hook_result *context::hook(void *target, void *new_func, bool require_origin) {

        int overwrite_len;
        int overwrite_ins_num;
        uint32_t overwrite_ins[4] = {0};
        size_t trampoline_len;
        size_t callee_save_trampoline_len;
        void* ins_save = nullptr;
        void* first_dest = new_func;
        auto pid = get_pid();
        void* back_trampoline;
        auto hook_save = new hook_result;
        // lock
        while (true) {
            while (hook_lock_.load() != 0); // wait
            hook_lock_.store(pid);
            if (hook_lock_.load() == pid) {
                break;
            }
        }

        if (require_origin) {
            first_dest = create_callee_save_trampoline(new_func, hook_save, &callee_save_trampoline_len);
        }

        overwrite_ins_num = 4;
        overwrite_len = AARCH64_INS_LEN*overwrite_ins_num;
        overwrite_ins[0] = 0x58000050; // LDR X16, #8
        overwrite_ins[1] = 0xd61f0200; // BR X16
        memcpy(&overwrite_ins[2], &first_dest, sizeof(void*));

        // make target address writable
        enable_page_write(target, overwrite_len);
        //ins_save = malloc(overwrite_len);
        ins_save = new char[overwrite_len];
        back_trampoline = create_trampoline(
            reinterpret_cast<char *>(target) + overwrite_len, target, overwrite_len, &trampoline_len
        );
        memcpy(ins_save, target, overwrite_len);

        {
            auto target_ins_ptr = reinterpret_cast<uint32_t*>(target);
            *target_ins_ptr = LOOP_INS; // loop at entry
            for (int i = 1; i < overwrite_ins_num; i++) {
                target_ins_ptr[i] = overwrite_ins[i];
            }
            target_ins_ptr[0] = overwrite_ins[0]; // change first instrument at last
        }

        disable_page_write(target, overwrite_len);
        hook_save->ctx_ = this;
        hook_save->origin_code_save_ = static_cast<char *>(ins_save);
        hook_save->origin_entry_address_ = target;
        hook_save->overwrite_bytes_num_ = overwrite_len;
        hook_save->trampoline_address_ = back_trampoline;
        hook_save->trampoline_len_ = trampoline_len;
        hook_save->callee_save_trampoline_ = first_dest == new_func ? nullptr : first_dest;
        hook_save->callee_save_trampoline_len_ = callee_save_trampoline_len;
        hook_map_[target] = hook_save;

        // unlock
        hook_lock_.store(0);
        return hook_save;

    }

}