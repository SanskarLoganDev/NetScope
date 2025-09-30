// include/netscope/parser.hpp
#pragma once
#include <cstdint>
#include "netscope/packet.hpp"

namespace netscope {

// Returns true if the packet is IPv4 + (TCP or UDP) and out is filled.
// Returns false if not parseable / not IPv4 / not TCP/UDP.
bool parse_packet(const uint8_t* data, uint32_t caplen, Packet& out);

} // namespace netscope
