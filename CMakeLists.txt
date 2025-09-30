# CMakeLists.txt (top-level)
cmake_minimum_required(VERSION 3.16)
project(netscope CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Core library with just parser + utils for now
add_library(netscope_core
    src/parser.cpp
    src/util.cpp
)
target_include_directories(netscope_core PUBLIC include)

# Tiny demo app
add_executable(decode_one app/decode_one.cpp)
target_link_libraries(decode_one PRIVATE netscope_core)
