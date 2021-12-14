#include <cstdlib>
#include <sys/mman.h>
#include "mm.h"
#include <cstring>

namespace hook {

    execute_mem_pool_item::execute_mem_pool_item(): write_request_(0) {
        next = nullptr;
        mem_start_ = mmap(nullptr, item_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
        memset(mem_start_, 0, item_size);
        *(reinterpret_cast<uint16_t *>(mem_start_) + 1) = item_size - 2*sizeof(uint16_t);
    }

    void *execute_mem_pool_item::alloc_mem(size_t len) {
        if (len > max_alloc_len) {
            return nullptr;
        }
        auto p = reinterpret_cast<unsigned char*>(mem_start_);
        size_t curr_index = 0;
        while (curr_index < item_size) {
            // pass used space
            auto flags = *reinterpret_cast<uint16_t *>(p+curr_index);
            auto item_len = *reinterpret_cast<uint16_t *>(p + curr_index + sizeof(uint16_t));
            if ((flags & flag_use) != 0) {
                curr_index += (header_size + item_len);
                continue;
            }

            // find real free size;
            size_t item_real_len = 0;
            auto start_index = curr_index;
            while (item_real_len < len) {
                auto this_flag = *reinterpret_cast<uint16_t *>(p + curr_index);
                auto this_item_len = *reinterpret_cast<uint16_t *>(p + curr_index + sizeof(uint16_t));
                if ((this_flag & flags ) != 0) {
                    break;
                }
                item_real_len += this_item_len;
                if (curr_index != start_index) {
                    item_real_len = header_size;
                }
                curr_index += header_size + this_item_len;
            }
            if (item_real_len >= len) {
                inc_write_request();
                *reinterpret_cast<uint16_t *>(p + start_index) |= flag_use;
                *reinterpret_cast<uint16_t *>(p + start_index + sizeof(uint16_t)) = len;
                if (item_real_len != len && len + start_index + 2 * sizeof(uint16_t) < item_size) {
                    *reinterpret_cast<uint16_t *>(p + start_index + header_size + len) &= ~flag_use;
                    *reinterpret_cast<uint16_t *>(p + start_index + header_size + sizeof(uint16_t) + len) = item_real_len - len;
                }
                return p + start_index + header_size;
            }
        }

        return nullptr;
    }

    void execute_mem_pool_item::free_mem(void *address, size_t len) {
        if (is_this_item(address)) {
            inc_write_request();
            *(reinterpret_cast<uint16_t*>(address) - 2) &= ~flag_use;
            dec_write_request();
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

    execute_mem_pool::~execute_mem_pool() {
        execute_mem_pool_item* p = head_;
        execute_mem_pool_item* up = nullptr;
        do {
            delete up;
            munmap(p->mem_start_, execute_mem_pool_item::item_size);
            up = p;
        } while ((p = p->next) != nullptr);
        delete up;
    }

}