// src/parser.cpp
#include "netscope/parser.hpp"
#include <cstring> // std::memcpy

namespace netscope {

bool parse_packet(const uint8_t* data, uint32_t caplen, Packet& out) {
    out = Packet{}; // zero/init all fields

    // Need Ethernet header (14 bytes)
    if (!data || caplen < 14) return false;

    // Ethernet: dst(0..5), src(6..11), type(12..13)
    out.has_eth = true;
    std::memcpy(out.eth_dst, data + 0, 6);
    std::memcpy(out.eth_src, data + 6, 6);
    const uint16_t eth_type = (uint16_t)((data[12] << 8) | data[13]);

    if (eth_type != 0x0800) { // 0x0800 = IPv4
        return false;         // ignore non-IPv4 for now
    }
    out.is_ipv4 = true;

    // IPv4 starts at byte 14
    if (caplen < 14 + 20) return false; // minimal IPv4 header
    const uint8_t* ip = data + 14;

    const uint8_t ver_ihl = ip[0];
    const uint8_t version = ver_ihl >> 4;
    const uint8_t ihl     = ver_ihl & 0x0F;  // 32-bit words
    const uint32_t iphdr_len = ihl * 4;
    if (version != 4 || iphdr_len < 20) return false;
    if (caplen < 14 + iphdr_len) return false;

    // total length (bytes 2..3, big-endian)
    out.ip_total_len = (uint16_t)((ip[2] << 8) | ip[3]);

    // src/dst IPv4
    std::memcpy(out.src_ip, ip + 12, 4);
    std::memcpy(out.dst_ip, ip + 16, 4);

    const uint8_t proto = ip[9];
    const uint8_t* l4 = ip + iphdr_len;

    if (proto == 6) { // TCP
        if (caplen < (uint32_t)(l4 - data) + 20) return false; // min TCP header
        out.is_tcp = true;
        out.src_port = (uint16_t)((l4[0] << 8) | l4[1]);
        out.dst_port = (uint16_t)((l4[2] << 8) | l4[3]);
        const uint8_t flags = l4[13];
        out.tcp_flags = flags; // caller can check bits
    } else if (proto == 17) { // UDP
        if (caplen < (uint32_t)(l4 - data) + 8) return false; // min UDP header
        out.is_udp = true;
        out.src_port = (uint16_t)((l4[0] << 8) | l4[1]);
        out.dst_port = (uint16_t)((l4[2] << 8) | l4[3]);
        out.tcp_flags = 0;
    } else {
        return false; // ignore other protocols for now
    }

    out.valid = true;
    return true;
}

} // namespace netscope
