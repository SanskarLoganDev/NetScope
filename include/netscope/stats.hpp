// include/netscope/stats.hpp
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "netscope/packet.hpp"

namespace netscope {

// existing:
void reset_stats();
void on_packet(const Packet& pkt);
void print_top_talkers(std::size_t topN = 5);
void print_top_flows(std::size_t topN = 5);

// NEW: lightweight row struct & getters so CLI can compute percentages
struct Row {
    std::string key;     // "a.b.c.d" or "a.b.c.d:p -> w.x.y.z:q TCP/UDP"
    std::uint64_t bytes; // total bytes attributed to this key
};

std::uint64_t total_bytes();                             // sum of all IPv4 bytes seen
std::vector<Row> top_talkers(std::size_t topN = 5);     // sorted desc
std::vector<Row> top_flows(std::size_t topN = 5);       // sorted desc

} // namespace netscope
