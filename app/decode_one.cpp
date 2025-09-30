// app/decode_one.cpp
#include "netscope/parser.hpp"
#include "netscope/util.hpp"
#include <cstdio>

using namespace netscope;

int main() {
    // Same synthetic Ethernet+IPv4+TCP (SYN) packet as before
    const uint8_t pkt[] = {
        // Ethernet (14 bytes)
        0x00,0x11,0x22,0x33,0x44,0x55,  // dst MAC
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,  // src MAC
        0x08,0x00,                      // IPv4

        // IPv4 (20 bytes)
        0x45,0x00, 0x00,0x28, 0x1C,0x46, 0x40,0x00, 0x40,0x06, 0x00,0x00,
        0xC0,0xA8,0x01,0x0A,            // 192.168.1.10
        0x5D,0xB8,0xD8,0x22,            // 93.184.216.34

        // TCP (20 bytes) SYN
        0xD4,0x31, 0x00,0x50,           // 54321 -> 80
        0x01,0x23,0x45,0x67,            // seq
        0x00,0x00,0x00,0x00,            // ack
        0x50, 0x02,                     // data offset=5, flags=SYN
        0xFF,0xFF, 0x00,0x00, 0x00,0x00 // win, cksum, urg
    };

    Packet p;
    if (!parse_packet(pkt, sizeof(pkt), p) || !p.valid) {
        std::puts("Failed to parse packet.");
        return 1;
    }

    std::puts("Ethernet:");
    std::printf("  dst="); print_mac(p.eth_dst);
    std::printf("\n  src="); print_mac(p.eth_src);
    std::printf("\n  type=0x0800 (IPv4)\n\n");

    std::puts("IPv4:");
    std::printf("  src="); print_ipv4(p.src_ip);
    std::printf("\n  dst="); print_ipv4(p.dst_ip);
    std::printf("\n  total_len=%u\n\n", p.ip_total_len);

    if (p.is_tcp) {
        bool syn = p.tcp_flags & 0x02;
        bool ack = p.tcp_flags & 0x10;
        bool fin = p.tcp_flags & 0x01;
        bool rst = p.tcp_flags & 0x04;

        std::puts("TCP:");
        std::printf("  src_port=%u dst_port=%u\n", p.src_port, p.dst_port);
        std::printf("  flags [SYN=%d ACK=%d FIN=%d RST=%d]\n", syn, ack, fin, rst);
    } else if (p.is_udp) {
        std::puts("UDP:");
        std::printf("  src_port=%u dst_port=%u\n", p.src_port, p.dst_port);
    }
    return 0;
}


// #include <cstdint>
// #include <cstdio>

// #ifdef _WIN32
//   #include <winsock2.h> // ntohs, ntohl
//   #pragma comment(lib, "ws2_32.lib")
// #else
//   #include <arpa/inet.h> // ntohs, ntohl
// #endif

// // Print 6-byte MAC as 00:11:22:33:44:55
// void print_mac(const uint8_t* p) {
//     std::printf("%02X:%02X:%02X:%02X:%02X:%02X",
//         p[0], p[1], p[2], p[3], p[4], p[5]);
// }

// // Print IPv4 as a.b.c.d (input is big-endian/network order)
// void print_ipv4(uint32_t be_ip) {
//     uint32_t ip = ntohl(be_ip);
//     std::printf("%u.%u.%u.%u",
//         (ip >> 24) & 0xFF,
//         (ip >> 16) & 0xFF,
//         (ip >> 8)  & 0xFF,
//         (ip)       & 0xFF);
// }

// int main() {
// #ifdef _WIN32
//     // Initialize Winsock so ntohs/ntohl are available safely on MSVC
//     WSADATA wsaData;
//     WSAStartup(MAKEWORD(2,2), &wsaData);
// #endif

//     // ONE Ethernet+IPv4+TCP packet (20B IP header + 20B TCP header; no payload)
//     const uint8_t pkt[] = {
//         // Ethernet (14 bytes)
//         0x00,0x11,0x22,0x33,0x44,0x55,  // dst MAC
//         0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,  // src MAC
//         0x08,0x00,                      // EtherType = 0x0800 (IPv4)

//         // IPv4 header (20 bytes)
//         0x45,       // Version(4)=4, IHL(4)=5 (i.e., 20-byte header)
//         0x00,       // DSCP/ECN
//         0x00,0x28,  // Total Length = 40 bytes (20 IP + 20 TCP)
//         0x1C,0x46,  // Identification
//         0x40,0x00,  // Flags/Frag offset (DF)
//         0x40,       // TTL = 64
//         0x06,       // Protocol = 6 (TCP)
//         0x00,0x00,  // Header checksum (ignored here)
//         0xC0,0xA8,0x01,0x0A,  // Src IP = 192.168.1.10
//         0x5D,0xB8,0xD8,0x22,  // Dst IP = 93.184.216.34

//         // TCP header (20 bytes)
//         0xD4,0x31,  // Src port = 54321
//         0x00,0x50,  // Dst port = 80 (HTTP)
//         0x01,0x23,0x45,0x67,  // Seq num
//         0x00,0x00,0x00,0x00,  // Ack num
//         0x50,       // Data offset(4 bits)=5 (20 bytes), then reserved bits
//         0x02,       // Flags: 0x02 = SYN
//         0xFF,0xFF,  // Window size
//         0x00,0x00,  // Checksum (ignored here)
//         0x00,0x00   // Urgent pointer
//     };

//     // 1) Decode Ethernet
//     const uint8_t* eth = pkt;
//     const uint8_t* eth_dst = eth + 0;
//     const uint8_t* eth_src = eth + 6;
//     uint16_t eth_type = static_cast<uint16_t>((pkt[12] << 8) | pkt[13]);

//     std::puts("Ethernet:");
//     std::printf("  dst=");
//     print_mac(eth_dst);
//     std::printf("\n  src=");
//     print_mac(eth_src);
//     std::printf("\n  type=0x%04X\n\n", eth_type);

//     if (eth_type != 0x0800) { // not IPv4
//         std::puts("Not IPv4. Exiting.");
//         return 0;
//     }

//     // 2) Decode IPv4
//     const uint8_t* ip = pkt + 14;
//     uint8_t ver_ihl = ip[0];
//     uint8_t version = ver_ihl >> 4;
//     uint8_t ihl = ver_ihl & 0x0F; // number of 32-bit words
//     uint16_t total_len = ntohs(*reinterpret_cast<const uint16_t*>(ip + 2));
//     uint8_t ttl = ip[8];
//     uint8_t proto = ip[9];
//     uint32_t src_ip = *reinterpret_cast<const uint32_t*>(ip + 12);
//     uint32_t dst_ip = *reinterpret_cast<const uint32_t*>(ip + 16);

//     std::printf("IPv4:\n  version=%u ihl=%u (bytes=%u)\n", version, ihl, ihl*4);
//     std::printf("  total_len=%u ttl=%u proto=%u\n", total_len, ttl, proto);
//     std::printf("  src=");
//     print_ipv4(src_ip);
//     std::printf("\n  dst=");
//     print_ipv4(dst_ip);
//     std::printf("\n\n");

//     if (proto != 6) { // not TCP
//         std::puts("Not TCP. Exiting.");
//         return 0;
//     }

//     // 3) Decode TCP
//     const uint8_t* tcp = ip + ihl*4;
//     uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp + 0));
//     uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp + 2));
//     uint32_t seq = ntohl(*reinterpret_cast<const uint32_t*>(tcp + 4));
//     uint32_t ack = ntohl(*reinterpret_cast<const uint32_t*>(tcp + 8));
//     uint8_t data_offset = (tcp[12] >> 4) & 0x0F; // in 32-bit words
//     uint8_t flags = tcp[13];
//     bool syn = (flags & 0x02) != 0;
//     bool ackf = (flags & 0x10) != 0;
//     bool fin = (flags & 0x01) != 0;
//     bool rst = (flags & 0x04) != 0;

//     std::printf("TCP:\n  src_port=%u dst_port=%u\n", src_port, dst_port);
//     std::printf("  seq=%u ack=%u\n", seq, ack);
//     std::printf("  data_offset=%u (bytes=%u)\n", data_offset, data_offset*4);
//     std::printf("  flags: [SYN=%d ACK=%d FIN=%d RST=%d]\n", syn, ackf, fin, rst);

// #ifdef _WIN32
//     WSACleanup();
// #endif
//     return 0;
// }
