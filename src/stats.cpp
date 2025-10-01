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

    // Build a sorted vector of netscope::Row from a map, descending by bytes
    std::vector<netscope::Row> make_sorted_rows(
        const std::unordered_map<std::string, std::uint64_t>& m,
        std::size_t topN
    ) {
        std::vector<netscope::Row> rows;
        rows.reserve(m.size());
        for (const auto& kv : m) {
            rows.push_back(netscope::Row{kv.first, kv.second});
        }
        std::sort(rows.begin(), rows.end(),
                  [](const netscope::Row& a, const netscope::Row& b){
                      return a.bytes > b.bytes;
                  });
        if (rows.size() > topN) rows.resize(topN);
        return rows;
    }

    // Pretty-print a list of rows with aligned keys
    void print_rows(const std::vector<netscope::Row>& rows,
                    const char* title, int keyWidth)
    {
        std::puts(title);
        if (rows.empty()) {
            std::puts("  (none)");
            return;
        }
        for (const auto& r : rows) {
            std::printf("  %-*s  %12s\n",
                        keyWidth,
                        r.key.c_str(),
                        netscope::human_bytes(r.bytes).c_str());
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

    const std::string key = flow_key(pkt.src_ip, pkt.src_port,
                                     pkt.dst_ip, pkt.dst_port, proto);
    g_bytes_by_flow[key] += pkt.ip_total_len;
}

void print_top_talkers(std::size_t topN) {
    print_rows(make_sorted_rows(g_bytes_by_src, topN),
               "\nTop Talkers (by bytes):", 15);
}

void print_top_flows(std::size_t topN) {
    print_rows(make_sorted_rows(g_bytes_by_flow, topN),
               "Top Flows (by bytes):", 50);
}

// --- NEW: totals + sorted rows for CLI percentages ---
std::uint64_t total_bytes() {
    std::uint64_t sum = 0;
    for (const auto& kv : g_bytes_by_src) sum += kv.second; // each byte counted once here
    return sum;
}

std::vector<Row> top_talkers(std::size_t topN) {
    return make_sorted_rows(g_bytes_by_src, topN);
}

std::vector<Row> top_flows(std::size_t topN) {
    return make_sorted_rows(g_bytes_by_flow, topN);
}

} // namespace netscope
