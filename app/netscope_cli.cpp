// app/netscope_cli.cpp
#include "netscope/parser.hpp"
#include "netscope/stats.hpp"
#include "netscope/util.hpp"

#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>   // std::strtoul

using namespace netscope;

static void print_one_line(const Packet& p) {
    if (!p.valid) return;
    if (p.is_tcp) {
        bool syn = p.tcp_flags & 0x02;
        bool ack = p.tcp_flags & 0x10;
        bool fin = p.tcp_flags & 0x01;
        bool rst = p.tcp_flags & 0x04;

        std::printf("TCP  ");
        print_ipv4(p.src_ip); std::printf(":%u  ->  ", p.src_port);
        print_ipv4(p.dst_ip); std::printf(":%u  flags[SYN=%d ACK=%d FIN=%d RST=%d]\n",
                                          p.dst_port, syn, ack, fin, rst);
    } else if (p.is_udp) {
        std::printf("UDP  ");
        print_ipv4(p.src_ip); std::printf(":%u  ->  ", p.src_port);
        print_ipv4(p.dst_ip); std::printf(":%u\n", p.dst_port);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::puts("Usage: netscope_cli <file.pcap> [--verbose] [--top N]");
        return 1;
    }

    const char* path = argv[1];
    bool verbose = false;
    std::size_t topN = 3;

    // very simple arg parse
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--verbose") == 0) verbose = true;
        else if (std::strcmp(argv[i], "--top") == 0 && i+1 < argc) {
            topN = (std::size_t)std::strtoul(argv[++i], nullptr, 10);
            if (topN == 0) topN = 3;
        }
    }

    char err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(path, err);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_offline failed: %s\n", err);
        return 1;
    }

    reset_stats();

    const u_char* data = nullptr;
    struct pcap_pkthdr* hdr = nullptr;
    int rc = 0, total = 0, parsed = 0;

    // duration tracking
    double first_ts = -1.0, last_ts = 0.0;

    while ((rc = pcap_next_ex(handle, &hdr, &data)) > 0) {
        ++total;

        double now = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
        if (first_ts < 0.0) first_ts = now;
        last_ts = now;

        Packet p;
        if (parse_packet(reinterpret_cast<const uint8_t*>(data), hdr->caplen, p) && p.valid) {
            ++parsed;
            if (verbose) print_one_line(p);
            on_packet(p);
        }
    }
    if (rc == -1) {
        std::fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);

    const double duration = (first_ts < 0.0) ? 0.0 : (last_ts - first_ts);
    const std::uint64_t totalBytes = total_bytes();

    std::printf("File: %s  Duration: %.2f s  Packets: %d  Parsed: %d  Total: %s\n",
                path, duration, total, parsed, human_bytes(totalBytes).c_str());

    // pull sorted rows for % printing
    auto tt = top_talkers(topN);
    auto tf = top_flows(topN);

    // Top Talkers
    std::puts("\nTop Talkers:");
    if (tt.empty()) {
        std::puts("  (none)");
    } else {
        for (const auto& r : tt) {
            std::printf("  %-15s  %10s  (%s)\n",
                r.key.c_str(),
                human_bytes(r.bytes).c_str(),
                percent_string(r.bytes, totalBytes).c_str());
        }
    }

    // Top Flows
    std::puts("\nTop Flows:");
    if (tf.empty()) {
        std::puts("  (none)");
    } else {
        for (const auto& r : tf) {
            std::printf("  %-50s  %10s  (%s)\n",
                r.key.c_str(),
                human_bytes(r.bytes).c_str(),
                percent_string(r.bytes, totalBytes).c_str());
        }
    }

    // -------- Verdict (very simple heuristic) --------
    std::puts("\nVerdict:");
    if (totalBytes == 0 || tt.empty()) {
        std::puts("  No TCP/UDP traffic recorded.");
        return 0;
    }

    const auto& top = tt.front(); // highest-source IP by bytes
    bool top_is_local = is_private_ipv4_str(top.key);
    // compute % as a number
    double top_pct = (double)top.bytes * 100.0 / (double)totalBytes;

    if (top_pct >= 60.0) {
        if (top_is_local) {
            std::printf("  Likely cause: **Upload saturation**. Local host %s sent %.1f%% of bytes.\n",
                        top.key.c_str(), top_pct);
            std::puts  ("  Action: Pause cloud sync/backups for a minute, or limit upload.");
        } else {
            std::printf("  Likely cause: **Download heavy**. Remote host %s sent %.1f%% of bytes to you.\n",
                        top.key.c_str(), top_pct);
            std::puts  ("  Action: Check active downloads/updates or streaming apps.");
        }
    } else if (top_pct >= 40.0) {
        std::printf("  A major talker exists (%s at %.1f%%), but not dominant.\n",
                    top.key.c_str(), top_pct);
        std::puts  ("  Action: Inspect Top Flows above; multiple apps may be sharing bandwidth.");
    } else {
        std::puts  ("  No single hog detected (top < 40%).");
        std::puts  ("  Action: Try moving closer to AP, switch band, or test ISP speed.");
    }

    return 0;
}
