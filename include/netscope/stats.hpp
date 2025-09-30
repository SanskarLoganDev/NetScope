// include/netscope/stats.hpp
#pragma once
#include <cstddef>
#include "netscope/packet.hpp"

namespace netscope {

void reset_stats();                           // clear all counters
void on_packet(const Packet& pkt);            // update counters from one parsed packet
void print_top_talkers(std::size_t topN = 5); // bytes by source IP
void print_top_flows(std::size_t topN = 5);   // bytes by src:port -> dst:port + proto

} // namespace netscope
