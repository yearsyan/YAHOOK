cmake_minimum_required(VERSION 3.10.0)
project(YAHOOK)

set(CMAKE_CXX_STANDARD 17)

add_library(YAHOOK hook.cpp hook.h mm.cpp mm.h)

MESSAGE("Build System: ${CMAKE_SYSTEM_NAME}")
if (CMAKE_SYSTEM_NAME MATCHES "Linux" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_executable(YAHOOK-example example/hook-example.cpp hook.h)
    target_link_libraries(YAHOOK-example YAHOOK)
elseif(CMAKE_SYSTEM_NAME MATCHES "Android" AND ENABLE_JNI)
    add_library(YAHOOK-Android SHARED jni-export.cpp hook.h)
    target_link_libraries(YAHOOK-Android android log YAHOOK)
    target_compile_definitions(YAHOOK-Android PRIVATE EXPORT_CLASS="io/github/yearsyan/YAHOOK")
endif()