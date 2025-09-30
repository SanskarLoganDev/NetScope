// include/netscope/packet.hpp
#pragma once
#include <cstdint>

namespace netscope {

// Minimal, reusable, POD-style struct
struct Packet {
    bool     valid = false;     // did parsing succeed?
    bool     is_ipv4 = false;
    bool     is_tcp  = false;
    bool     is_udp  = false;

    // Ethernet (optional but nice for printing)
    bool     has_eth = false;
    uint8_t  eth_dst[6]{};
    uint8_t  eth_src[6]{};

    // IPv4
    uint8_t  src_ip[4]{};       // 4 bytes: a.b.c.d
    uint8_t  dst_ip[4]{};
    uint16_t ip_total_len = 0;  // total length (header + payload), in bytes

    // L4
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  tcp_flags = 0;     // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04 (if TCP)
};

} // namespace netscope
