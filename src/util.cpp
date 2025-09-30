// src/util.cpp
#include "netscope/util.hpp"
#include <cstdio>

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

} // namespace netscope
