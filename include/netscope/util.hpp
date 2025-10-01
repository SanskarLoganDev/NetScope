// include/netscope/util.hpp
#pragma once
#include <cstdint>
#include <string>

namespace netscope {

void print_ipv4(const uint8_t* p); // a.b.c.d to stdout
std::string ipv4_to_string(const uint8_t* p);
std::string human_bytes(uint64_t b);
std::string flow_key(const uint8_t* sip, uint16_t sport,
                     const uint8_t* dip, uint16_t dport,
                     uint8_t proto);
// optional: small MAC printer for the demo
void print_mac(const uint8_t* p);

// classify private/local IPs and format percentages
bool is_private_ipv4(const uint8_t* p);
bool is_private_ipv4_str(const std::string& s);
std::string percent_string(std::uint64_t part, std::uint64_t whole);

} // namespace netscope
