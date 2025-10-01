# NetScope — Wi-Fi Hog Finder (C++/libpcap)

## What problem does this solve?

When the network “feels slow,” you don’t know **what** is eating bandwidth. Is it a browser download, a cloud-sync upload, or something else?
**NetScope** gives a quick, human-readable answer from real traffic — not guesses.

## What it does (MVP)

* **Reads a `.pcap`** (packet capture file) and decodes Ethernet → IPv4 → TCP/UDP.
* Prints **Top Talkers** (which IP sent the most bytes) and **Top Flows** (which connection moved the most bytes).
* Shows **percentages** and a one-line **Verdict** (likely **upload** vs **download** heavy) with a simple action you can take.
* **DNS labeling:** if DNS responses are in the same capture, flows display **IP (domain)** (e.g., `23.215.0.136 (akamaiedge.net)`), so it’s obvious which site/app is responsible.

> Works great for quick triage: “Pause OneDrive upload”, “Stop the big download”, or “No single hog—check Wi-Fi/ISP.”

---

## How it works

1. You record a short capture (30–60s) during the slowdown.
2. NetScope reads headers (IPs, ports, sizes) — no decryption — and totals bytes per IP/flow.
3. It prints a compact report with percentages and a verdict.

---

## Repository layout

```
NetScope/
├─ CMakeLists.txt            # builds a tiny library + two apps
├─ README.md
├─ include/
│  └─ netscope/
│     ├─ packet.hpp          # 1 tiny data struct shared by all modules
│     ├─ parser.hpp          # "bytes -> Packet" (Ethernet/IPv4/TCP/UDP)
│     ├─ stats.hpp           # update counters + print Top Talkers/Flows
│     ├─ util.hpp            # helpers: IP formatting, flow keys, human bytes
|     └─ dns.hpp             # tiny DNS cache (IP -> domain) from DNS responses
├─ src/
│  ├─ parser.cpp             # implementation of parser.hpp
│  ├─ stats.cpp              # implementation of stats.hpp
│  ├─ util.cpp               # implementation of util.hpp (small helpers)
|  └─ dns.cpp                # implementation of dns.hpp
└─ app/
   ├─ netscope_cli.cpp       # main tool: read .pcap, use parser + stats
   └─ decode_one.cpp         # the tiny “one hard-coded packet” demo
```
---

## Requirements

* Linux/WSL or Ubuntu (Debian-based).
* Packages: `build-essential`, `cmake`, `libpcap-dev`, `tcpdump`

  ```bash
  sudo apt update
  sudo apt install -y build-essential cmake libpcap-dev tcpdump
  ```
* (For Windows traffic) Wireshark + **Npcap** on Windows to capture and save a `.pcap`.

> If HTTPS downloads fail in WSL with `SSL certificate problem`, install CA certs:
>
> ```bash
> sudo apt install -y ca-certificates openssl
> sudo update-ca-certificates
> ```

---

## Build (out-of-source)

> If your repo lives on a Windows drive (e.g., `E:`), generate build files **in Linux home** to avoid WSL mount quirks.

**Exact commands (as requested):**

```bash
# To make the directory in root:
mkdir -p ~/netscope_build

# Point CMake at your repo folder (adjust the path to your repo)
cmake /mnt/e/Coding-practice/Projects/NetScope
cmake --build . -j
```

If your repo is elsewhere, just replace `/mnt/e/Coding-practice/Projects/NetScope` with your path (e.g., `/home/you/NetScope`).

This builds:

* `./decode_one` (tiny demo)
* `./netscope_cli` (the main tool)

---

## Quick start: capture & analyze in WSL

### 1) See your interfaces (WSL2 uses `eth0`)

```bash
ip -br link
```

### 2) Start a short capture (200 TCP/UDP packets) and save it

```bash
# Capture ~200 TCP/UDP packets on eth0 and save to a new file
sudo tcpdump -i eth0 -c 200 '(tcp or udp) and not port 22' -w ~/fresh_eth.pcap
```

> If you still have the legacy sample command, it’s fine to keep in README:
>
> ```bash
> ./pcap_read ~/sample_eth.pcap
> ```
>
> (In this modular version you’ll mainly use `netscope_cli` below.)

### 3) Analyze the capture

```bash
cd ~/netscope_build
./netscope_cli ~/fresh_eth.pcap --verbose   # see per-packet lines
./netscope_cli ~/fresh_eth.pcap             # summary only
```

Shorthand examples:

```bash
# summary-only (default)
./netscope_cli ~/fresh_eth.pcap

# with per-packet lines
./netscope_cli ~/fresh_eth.pcap --verbose

# top 5 rows instead of 3
./netscope_cli ~/fresh_eth.pcap --top 5
```

### 4) Generate traffic (feeds DNS + flows) — examples to run while capturing

```bash
# 1) Trigger DNS + HTTPS to popular domains
curl -I https://www.google.com
curl -I https://www.microsoft.com
curl -I https://www.apple.com

# 2) Download a small chunk to create more visible flow bytes (5 MB)
curl -L https://speed.hetzner.de/100MB.bin --range 0-5242879 -o /dev/null --insecure

# 3) Ping by name (creates DNS request first, then ICMP)
ping -c 3 example.com

# (Note: ICMP echo packets themselves won't appear in our TCP/UDP-only tool,
# but the DNS lookup for 'example.com' WILL appear and feed the DNS cache.)
```

> **Tip for DNS labels in WSL:** WSL2 often proxies DNS through Windows, so UDP:53 may not appear on `eth0`.
> To force visible DNS in WSL captures, you can use `dig` directly to a resolver while capturing:
>
> ```bash
> sudo tcpdump -i eth0 -c 300 '(tcp or udp) and not port 22' -w ~/dns_test.pcap
> # in another terminal:
> sudo apt install -y dnsutils
> dig A google.com @8.8.8.8
> dig A microsoft.com @1.1.1.1
> curl -I https://www.google.com
> ```

---

## Analyze **Windows apps** (Chrome/Edge/OneDrive/etc.)

1. On Windows, install **Wireshark** (includes **Npcap**).
2. Start capture on your **Wi-Fi/Ethernet** (or **VPN**) adapter; browse/download for ~30–60s.
3. Stop and **File → Save As…** `.pcap` to Desktop, e.g., `windows_capture.pcap`.
4. In WSL:

   ```bash
   ./netscope_cli "/mnt/c/Users/<you>/Desktop/windows_capture.pcap" --top 5
   ```

This will include your browser/cloud-sync traffic and usually shows DNS responses, so you’ll see **IP (domain)** labels in Top Flows.

---

## What the report looks like (example)

```
File: dns_test.pcap  Duration: 45.12 s  Packets: 512  Parsed: 498  Total: 48.2 MB

Top Talkers:
  192.168.1.23           31.6 MB  (65.6%)
  23.215.0.136           14.1 MB  (29.2%)
  185.125.190.58          1.2 MB  ( 2.5%)

Top Flows:
  192.168.1.23:45306 -> 23.215.0.136 (akamaiedge.net):443 TCP    29.9 MB  (62.0%)
  23.215.0.136:443 -> 192.168.1.23:45306 TCP                     12.7 MB  (26.3%)

Verdict:
  Likely cause: Upload saturation. Local host 192.168.1.23 sent 62.0% of bytes.
  Action: Pause cloud sync/backups for a minute, or limit upload.
```

---

## Troubleshooting

* **Permission denied** running `tcpdump` → prefix commands with `sudo`.
* **No DNS labels** → your capture didn’t include DNS responses (WSL proxy, caching, DoH/DoT).

  * Capture on **Windows** with Wireshark, or use `dig @8.8.8.8` during WSL capture.
* **HTTPS cert errors in WSL** → update CA certificates:

  ```bash
  sudo apt install -y ca-certificates openssl
  sudo update-ca-certificates
  ```
* **Nothing shows** → ensure you’re capturing on the active interface (`ip -br link`), and generate traffic while capturing.

---

## Why not just use Wireshark?

Wireshark is amazing but verbose. **NetScope** is:

* **Targeted:** only the KPIs you care about (top talkers/flows, % , verdict).
* **Headless/scriptable:** run over SSH/CI, share a one-screen report.
* **Educational:** small C++17 codebase that’s easy to read for interviews and learning.

---

## License / Credits

Personal learning project inspired by classic packet analysis workflows. Uses **libpcap** for reading `.pcap` files.