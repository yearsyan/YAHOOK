cmake_minimum_required(VERSION 3.16)
project(YAHOOK)

set(CMAKE_CXX_STANDARD 17)

add_library(YAHOOK SHARED hook.cpp hook.h)

add_executable(YAHOOK-test hook-test.cpp hook.h)
target_link_libraries(YAHOOK-test YAHOOK)