// src/util.cpp
#include "netscope/util.hpp"
#include <cstdio>
#include <cinttypes>

namespace netscope {

void print_ipv4(const uint8_t* p) {
    std::printf("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

std::string ipv4_to_string(const uint8_t* p) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return std::string(buf);
}

std::string human_bytes(uint64_t b) {
    const char* u[] = {"B","KB","MB","GB","TB"};
    int i = 0;
    double x = (double)b;
    while (x >= 1024.0 && i < 4) { x /= 1024.0; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %s", x, u[i]);
    return std::string(buf);
}

std::string flow_key(const uint8_t* sip, uint16_t sport,
                     const uint8_t* dip, uint16_t dport,
                     uint8_t proto) {
    char buf[96];
    std::snprintf(buf, sizeof(buf),
        "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u %s",
        sip[0],sip[1],sip[2],sip[3], sport,
        dip[0],dip[1],dip[2],dip[3], dport,
        (proto==6 ? "TCP" : (proto==17 ? "UDP" : "OTHER")));
    return std::string(buf);
}

void print_mac(const uint8_t* p) {
    std::printf("%02X:%02X:%02X:%02X:%02X:%02X",
                p[0],p[1],p[2],p[3],p[4],p[5]);
}

bool is_private_ipv4(const uint8_t* p) {
    // 10.0.0.0/8
    if (p[0] == 10) return true;
    // 172.16.0.0/12  (172.16 - 172.31)
    if (p[0] == 172 && (p[1] >= 16 && p[1] <= 31)) return true;
    // 192.168.0.0/16
    if (p[0] == 192 && p[1] == 168) return true;
    // loopback 127.0.0.0/8
    if (p[0] == 127) return true;
    // link-local 169.254.0.0/16
    if (p[0] == 169 && p[1] == 254) return true;
    return false;
}

bool is_private_ipv4_str(const std::string& s) {
    unsigned a=0,b=0,c=0,d=0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return false;
    uint8_t p[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    return is_private_ipv4(p);
}

std::string percent_string(std::uint64_t part, std::uint64_t whole) {
    double pct = (whole == 0) ? 0.0 : (100.0 * (double)part / (double)whole);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.1f%%", pct);
    return std::string(buf);
}

} // namespace netscope
