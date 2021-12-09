#include <iostream>
#include "hook.h"

int get_r(int n) {
    int ret = 1;
    for (int i = 1; i < n; i++) {
        ret *= i;
    }
    return ret;
}

int r_123(int n) {
    return 123;
}

int main() {
    hook::context ctx;
    std::cout << get_r(10) << "\n";
    auto hook_ctx = ctx.hook((void*)get_r, (void*)r_123);
    std::cout << get_r(10) << "\n";
    ctx.unhook(hook_ctx);
    std::cout << get_r(10) << "\n";
    return 0;
}