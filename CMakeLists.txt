cmake_minimum_required(VERSION 3.16)
project(netscope CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(decode_one src/decode_one.cpp)
add_executable(pcap_read src/pcap_read.cpp)
target_link_libraries(pcap_read PRIVATE pcap)

