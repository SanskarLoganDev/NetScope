// app/netscope_cli.cpp
#include "netscope/parser.hpp"
#include "netscope/stats.hpp"
#include "netscope/util.hpp"

#include <pcap.h>
#include <cstdio>
#include <cstring>   // std::strcmp
#include <string>

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
        std::puts("Usage: netscope_cli <file.pcap> [--verbose]");
        return 1;
    }

    const char* path = argv[1];
    bool verbose = (argc >= 3 && std::strcmp(argv[2], "--verbose") == 0);

    char err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(path, err);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_offline failed: %s\n", err);
        return 1;
    }

    reset_stats();

    const u_char* data = nullptr;
    struct pcap_pkthdr* hdr = nullptr;   // pcap fills this
    int rc = 0, total = 0, parsed = 0;

    while ((rc = pcap_next_ex(handle, &hdr, &data)) > 0) {
        ++total;

        // Convert pcap's u_char* to uint8_t* for our parser
        Packet p;
        if (parse_packet(reinterpret_cast<const uint8_t*>(data), hdr->caplen, p) && p.valid) {
            ++parsed;
            if (verbose) print_one_line(p);
            on_packet(p); // update stats
        }
    }

    if (rc == -1) {
        std::fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);

    std::printf("Processed %d packets (%d parsed IPv4 TCP/UDP).\n", total, parsed);
    print_top_talkers(5);
    print_top_flows(5);
    return 0;
}
