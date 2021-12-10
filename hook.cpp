#include "hook.h"

#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cstring>
#include <cstdlib>

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

    // TODO: use mem pool
    void *context::alloc_code_mem(std::size_t len) {
        return mmap(nullptr, len, PROT_WRITE | PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    }

    void context::code_commit(void *address, size_t len) {
        mprotect(address, len, PROT_READ | PROT_EXEC);
    }

    void context::release_code(void *address, std::size_t len) {
        munmap(address, len);
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
        free(res->origin_code_save_);
        release_code(res->trampoline_address_, res->trampoline_len_);
        hook_map_.erase(res->origin_entry_address_);
        delete res;

        hook_lock_.store(0);
    }

    hook_result *context::hook(void *target, void *new_func) {

        // lock
        int overwrite_len;
        int overwrite_ins_num;
        uint32_t overwrite_ins[4] = {0};
        size_t trampoline_len;
        void* ins_save = nullptr;
        auto pid = get_pid();
        void* back_trampoline;
        while (true) {
            while (hook_lock_.load() != 0); // wait
            hook_lock_.store(pid);
            if (hook_lock_.load() == pid) {
                break;
            }
        }

        int64_t address_delta = PAGE_ADDRESS_OF(new_func) - PAGE_ADDRESS_OF(target);
        if (address_delta < 0xffffffff && address_delta > -0xffffffff) {
            // 3 instrument
            overwrite_ins_num = 3;
            overwrite_len = AARCH64_INS_LEN*overwrite_ins_num;
            overwrite_ins[0] = 0x90000010 |  ((address_delta & 0x3000)  << 17) | ((address_delta & 0xfffc000) >> 9);
            overwrite_ins[1] = 0x91000210 | ((0xfff & reinterpret_cast<long long>(new_func)) << 10);
            overwrite_ins[2] = 0xd61f0200;

        } else {
            overwrite_ins_num = 4;
            overwrite_len = AARCH64_INS_LEN*overwrite_ins_num;
            overwrite_ins[0] = 0x58000050;
            overwrite_ins[1] = 0xd61f0200;
            memcpy(&overwrite_ins[2], &new_func, sizeof(void*));

        }

        // make target address writable
        enable_page_write(target, overwrite_len);
        ins_save = malloc(overwrite_len);
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
        auto hook_save = new hook_result;
        hook_save->origin_code_save_ = ins_save;
        hook_save->origin_entry_address_ = target;
        hook_save->overwrite_bytes_num_ = overwrite_len;
        hook_save->trampoline_address_ = back_trampoline;
        hook_save->trampoline_len_ = trampoline_len;
        hook_map_[target] = hook_save;

        // unlock
        hook_lock_.store(0);
        return hook_save;

    }

}