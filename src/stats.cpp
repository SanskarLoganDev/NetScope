// src/stats.cpp
#include "netscope/stats.hpp"
#include "netscope/util.hpp"

#include <unordered_map>
#include <vector>
#include <algorithm>
#include <string>
#include <cstdio>
#include <cstdint>

namespace {
    // Internal counters (not exposed outside this file)
    std::unordered_map<std::string, std::uint64_t> g_bytes_by_src;   // key: "a.b.c.d"
    std::unordered_map<std::string, std::uint64_t> g_bytes_by_flow;  // key: "a.b.c.d:p -> w.x.y.z:q TCP/UDP"

    using Row = std::pair<std::string, std::uint64_t>;

    void print_top_map(const std::unordered_map<std::string, std::uint64_t>& m,
                       const char* title, std::size_t topN, int keyWidth) {
        std::vector<Row> rows(m.begin(), m.end());
        std::sort(rows.begin(), rows.end(),
                  [](const Row& a, const Row& b){ return a.second > b.second; });

        std::puts(title);
        if (rows.empty()) { std::puts("  (none)"); return; }

        std::size_t shown = 0;
        for (const auto& [k, bytes] : rows) {
            std::printf("  %-*s  %12s\n", keyWidth, k.c_str(), netscope::human_bytes(bytes).c_str());
            if (++shown >= topN) break;
        }
    }
} // anonymous namespace

namespace netscope {

void reset_stats() {
    g_bytes_by_src.clear();
    g_bytes_by_flow.clear();
}

void on_packet(const Packet& pkt) {
    if (!pkt.valid || !pkt.is_ipv4 || pkt.ip_total_len == 0)
        return;

    // Count bytes by source IP
    g_bytes_by_src[ipv4_to_string(pkt.src_ip)] += pkt.ip_total_len;

    // Count bytes by flow (requires TCP or UDP)
    uint8_t proto = pkt.is_tcp ? 6 : (pkt.is_udp ? 17 : 0);
    if (proto == 0) return;

    const std::string key = flow_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, proto);
    g_bytes_by_flow[key] += pkt.ip_total_len;
}

void print_top_talkers(std::size_t topN) {
    print_top_map(g_bytes_by_src,  "\nTop Talkers (by bytes):", topN, 15);
}

void print_top_flows(std::size_t topN) {
    print_top_map(g_bytes_by_flow, "Top Flows (by bytes):",    topN, 50);
}

} // namespace netscope
