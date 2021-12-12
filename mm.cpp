#include <cstdlib>
#include <sys/mman.h>
#include "mm.h"

namespace hook {

    execute_mem_pool_item::execute_mem_pool_item(): write_request_(0) {
        next = nullptr;
        mem_start_ = mmap(nullptr, item_size, PROT_EXEC | PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    }

    void *execute_mem_pool_item::alloc_mem(size_t len) {
        if (len > max_alloc_len) {
            return nullptr;
        }
        size_t unit_need = len/unit_size + 1;
        for (int unit_idx = 0; unit_idx < unit_count; unit_idx++) {
            if(has_free(unit_idx, unit_need)) {
                {
                    //set bits
                    for(int curr_unit_idx = unit_idx; curr_unit_idx < unit_idx + unit_need; curr_unit_idx++) {
                        int arr_index = curr_unit_idx / 64;
                        int bit_off = curr_unit_idx % 64;
                        bit_map_[arr_index] |= (1 << bit_off);
                    }
                }
                inc_write_request();
                return reinterpret_cast<uint64_t*>(mem_start_) + unit_idx;
            }
        }
        return nullptr;
    }

    void execute_mem_pool_item::free_mem(void *address, size_t len) {
        size_t unit_use = len/unit_size + 1;
        size_t unit_idx = (reinterpret_cast<unsigned long>(address) - reinterpret_cast<unsigned long >(mem_start_))/unit_size;
        for(size_t curr_unit_idx = unit_idx; curr_unit_idx < unit_idx + unit_use; curr_unit_idx++) {
            auto arr_index = curr_unit_idx / 64;
            auto bit_off = curr_unit_idx % 64;
            bit_map_[arr_index] &= (~(1 << bit_off));
        }
    }

    void execute_mem_pool_item::inc_write_request() {
        atomic_fetch_add(&write_request_,1);
        if (write_request_.load() == 1) {
            mprotect(mem_start_, item_size, PROT_EXEC | PROT_READ | PROT_WRITE);
        }
    }

    void execute_mem_pool_item::dec_write_request() {
        std::atomic_fetch_sub(&write_request_, 1);
        if (write_request_.load() == 0) {
            mprotect(mem_start_, item_size, PROT_READ | PROT_EXEC);
        }
    }

    bool execute_mem_pool_item::is_this_item(void *address) {
        auto l = reinterpret_cast<unsigned long>(address);
        return (l >= reinterpret_cast<unsigned long>(mem_start_)) &&
                (l < reinterpret_cast<unsigned long>(mem_start_) + item_size);
    }

    bool execute_mem_pool_item::has_free(int unit_index, size_t unit_need) {
        static const auto get_bit = [this](int curr_unit_index) {
            int arr_index = curr_unit_index / 64;
            int bit_off = curr_unit_index % 64;
            return (bit_map_[arr_index] & (1 << bit_off)) != 0;
        };
        for (int i = 0;i < unit_need;i++) {
            if (get_bit(unit_index+i)) {
                return false;
            }
        }
        return true;
    }

    execute_mem_pool::execute_mem_pool() {
        head_ = new execute_mem_pool_item;
        tail_ = head_;
    }

    void *execute_mem_pool::alloc_mem(size_t len) {
        execute_mem_pool_item* p = head_;
        do {
            auto res = p->alloc_mem(len);
            if (res != nullptr) {
                return res;
            }
        } while ((p = p->next) != nullptr);
        tail_->next = new execute_mem_pool_item;
        tail_ = tail_->next;
        return tail_->alloc_mem(len);
    }

    void execute_mem_pool::free_mem(void *address, size_t len) {
        execute_mem_pool_item* p = head_;
        do {
            if (p->is_this_item(address)) {
                p->free_mem(address, len);
            }
        } while ((p = p->next) != nullptr);
    }

    void execute_mem_pool::code_write_done(void *address, size_t len) {
        execute_mem_pool_item* p = head_;
        do {
            if (p->is_this_item(address)) {
                p->dec_write_request();
            }
        } while ((p = p->next) != nullptr);
    }

}