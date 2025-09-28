#include <pcap.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>

// ------- helpers (printing & formatting) -------

static void print_ipv4(const u_char* p) {
    std::printf("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static std::string ipv4_to_string(const u_char* p) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return std::string(buf);
}

static std::string human_bytes(uint64_t b) {
    const char* u[] = {"B","KB","MB","GB","TB"};
    int i = 0;
    double x = (double)b;
    while (x >= 1024.0 && i < 4) { x /= 1024.0; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %s", x, u[i]);
    return std::string(buf);
}

static std::string flow_key(const u_char* sip, uint16_t sport,
                            const u_char* dip, uint16_t dport,
                            uint8_t proto) {
    char buf[80];
    std::snprintf(buf, sizeof(buf),
        "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u %s",
        sip[0],sip[1],sip[2],sip[3], sport,
        dip[0],dip[1],dip[2],dip[3], dport,
        (proto==6 ? "TCP" : (proto==17 ? "UDP" : "OTHER")));
    return std::string(buf);
}

// ------- simple counters -------
static std::unordered_map<std::string, uint64_t> g_bytes_by_src;   // bytes per source IP
static std::unordered_map<std::string, uint64_t> g_bytes_by_flow;  // bytes per 5-tuple flow

// Parse ONE packet and optionally print a one-line summary if IPv4 + TCP/UDP
static void parse_and_print(const u_char* data, uint32_t caplen) {
    // 1) Need at least Ethernet header (14 bytes)
    if (caplen < 14) return;

    // Ethernet: bytes 12..13 = EtherType
    uint16_t eth_type = (uint16_t)(data[12] << 8 | data[13]);
    if (eth_type != 0x0800) return; // only handle IPv4 here

    // 2) IPv4 header starts at byte 14
    const u_char* ip = data + 14;
    if (caplen < 14 + 20) return; // minimal IPv4 header size
    uint8_t ver_ihl = ip[0];
    uint8_t version = ver_ihl >> 4;
    uint8_t ihl = ver_ihl & 0x0F;       // header length in 32-bit words
    uint32_t iphdr_len = ihl * 4;       // convert to bytes
    if (version != 4 || iphdr_len < 20) return;
    if (caplen < 14 + iphdr_len) return;

    // total IPv4 packet length (header + payload) — good for byte counting
    uint16_t ip_total_len = (uint16_t)(ip[2] << 8 | ip[3]);

    uint8_t proto = ip[9];
    const u_char* src_ip = ip + 12;
    const u_char* dst_ip = ip + 16;

    // count bytes by SOURCE IP (talker)
    g_bytes_by_src[ipv4_to_string(src_ip)] += ip_total_len;

    // 3) Next header (TCP or UDP) begins after the IP header
    const u_char* l4 = ip + iphdr_len;

    if (proto == 6) { // TCP
        if (caplen < (uint32_t)(l4 - data) + 20) return; // minimal TCP header
        uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
        uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
        uint8_t flags = l4[13];
        bool syn = flags & 0x02;
        bool ack = flags & 0x10;
        bool fin = flags & 0x01;
        bool rst = flags & 0x04;

        // count flow bytes
        g_bytes_by_flow[flow_key(src_ip, sport, dst_ip, dport, proto)] += ip_total_len;

        std::printf("TCP  ");
        print_ipv4(src_ip); std::printf(":%u  ->  ", sport);
        print_ipv4(dst_ip); std::printf(":%u  flags[SYN=%d ACK=%d FIN=%d RST=%d]\n",
                                        dport, syn, ack, fin, rst);
    } else if (proto == 17) { // UDP
        if (caplen < (uint32_t)(l4 - data) + 8) return; // minimal UDP header
        uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
        uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);

        // count flow bytes
        g_bytes_by_flow[flow_key(src_ip, sport, dst_ip, dport, proto)] += ip_total_len;

        std::printf("UDP  ");
        print_ipv4(src_ip); std::printf(":%u  ->  ", sport);
        print_ipv4(dst_ip); std::printf(":%u\n", dport);
    } else {
        // other protocols ignored in this simple reader
        return;
    }
}

static void print_top_talkers(size_t topN = 5) {
    std::vector<std::pair<std::string, uint64_t>> rows(g_bytes_by_src.begin(), g_bytes_by_src.end());
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    std::puts("\nTop Talkers (by bytes sent):");
    size_t shown = 0;
    for (const auto& [ip, bytes] : rows) {
        std::printf("  %-15s  %12s\n", ip.c_str(), human_bytes(bytes).c_str());
        if (++shown >= topN) break;
    }
}

static void print_top_flows(size_t topN = 5) {
    std::vector<std::pair<std::string, uint64_t>> rows(g_bytes_by_flow.begin(), g_bytes_by_flow.end());
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    std::puts("\nTop Flows (by bytes):");
    size_t shown = 0;
    for (const auto& [flow, bytes] : rows) {
        std::printf("  %-40s  %12s\n", flow.c_str(), human_bytes(bytes).c_str());
        if (++shown >= topN) break;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::puts("Usage: pcap_read <file.pcap>");
        return 1;
    }

    char err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(argv[1], err);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_offline failed: %s\n", err);
        return 1;
    }

    const u_char* data = nullptr;
    struct pcap_pkthdr* hdr = nullptr;   // must be non-const for pcap_next_ex

    int rc = 0, count = 0;
    while ((rc = pcap_next_ex(handle, &hdr, &data)) > 0) {
        parse_and_print(data, hdr->caplen);
        ++count;
    }
    if (rc == -1) {
        std::fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);

    std::printf("Processed %d packets.\n", count);
    print_top_talkers(5);   // change number here if you want
    print_top_flows(5);     // change number here if you want
    return 0;
}
