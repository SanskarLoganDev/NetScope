# CMakeLists.txt (top-level)
cmake_minimum_required(VERSION 3.16)
project(netscope CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Core library (no external deps)
add_library(netscope_core
    src/parser.cpp
    src/util.cpp
    src/stats.cpp           # <-- NEW
)
target_include_directories(netscope_core PUBLIC include)

# Tiny demo app (hard-coded packet)
add_executable(decode_one app/decode_one.cpp)
target_link_libraries(decode_one PRIVATE netscope_core)

# Main CLI (reads .pcap with libpcap)
add_executable(netscope_cli app/netscope_cli.cpp)
target_link_libraries(netscope_cli PRIVATE netscope_core pcap)
