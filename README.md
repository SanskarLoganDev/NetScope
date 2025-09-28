---

# NetScope Starter (Beginner-Friendly)

## What problem does it solve?

When the network “feels slow,” you usually don’t know why. Is it your Wi-Fi? DNS? A single app hogging bandwidth? A flaky server?
**NetScope** gives a quick, human-readable answer from real traffic—not guesses.

## What it actually accomplishes (MVP)

In 60–90 seconds of observation, it prints a short diagnosis:

* **Top talkers & flows:** “What device/app is using most bandwidth right now?”
* **Connection health signals:**

  * **Handshake RTT** (time to first response) → rough latency to services
  * **Retransmits / SYN-without-ACK** → congestion or unreachable services
* **Simple verdicts:** “Zoom is fine; OneDrive is saturating upload,” or “High SYN failures to api.example.com—service likely down or blocked.”

This turns raw bytes → actionable hints a person can act on (pause a sync, switch AP, check ISP, or open a firewall).

## Concrete real-world uses

* **Home/Student:** “Why is my Wi-Fi laggy?” Find the bandwidth hog in seconds.
* **TA/IT helpdesk:** Quick triage during office hours or lab classes.
* **Dev/QA:** After a deploy, verify service reachability/latency without heavy tools.
* **Edge/Embedded vibe:** Run on a tiny VM or Pi to watch traffic headlessly.

## Why not just use Wireshark?

Wireshark is amazing but heavy and verbose. **NetScope** is:

* **Targeted** (just the KPIs you care about)
* **Headless/Scriptable** (CI, SSH, servers)
* **Small C++ codebase** you can reason about (great for learning + interviews)

---

## Starter program (what this repo includes first)

This tiny C++ program decodes a **single** Ethernet → IPv4 → TCP packet from a hard-coded byte array.
It prints human-readable fields (MACs, IPs, ports, flags). This is the first stepping stone toward a simple network analyzer.

---

## Setup

### For setting up WSL in your project/github folder

```bash
wsl --install -d Ubuntu
```

### Inside WSL

```bash
sudo apt update
sudo apt install -y build-essential cmake
```

---

## Building in WSL (with source on your Windows drive)

> **If you try to run `cmake ..` on a Windows drive:**
> You ran CMake inside a folder that lives on your Windows drive (`/mnt/e/...`). On WSL, Windows drives are mounted with special options that sometimes block certain file ops CMake does when it “generates” build files (e.g., `configure_file`, changing metadata/timestamps). Result: CMake can’t write the files it needs → configure step fails → no Makefile → nothing builds.

**Solution (generate/build in Linux home):**

```bash
mkdir -p ~/netscope_build
cd ~/netscope_build

cmake /mnt/e/Coding-practice/Projects/NetScope
cmake --build . -j
./decode_one
```

### What you just did (in plain words)

* Your **source code** lives on Windows: `/mnt/e/Coding-practice/Projects/NetScope`
* You created a **build folder** in Linux (WSL) home: `~/netscope_build`
* You told CMake: “**Read** the sources from the Windows folder, but **write** all build files (Makefiles, the compiled program) here in Linux.”

**Commands you ran:**

* `cmake /mnt/e/.../NetScope`
  → CMake read `CMakeLists.txt` from the Windows path and generated build files in `~/netscope_build`.
* `cmake --build . -j`
  → Used those build files to compile your code with g++.
  → Output: the executable `./decode_one` ended up in `~/netscope_build`.
* `./decode_one`
  → You ran the compiled program, which printed the Ethernet/IP/TCP fields.

This worked because writing build files on Windows-mounted drives can hit permission quirks in WSL; writing them in Linux home avoids that.

> **Tip (VS Code):** To *see* `~/netscope_build` from VS Code, use the **WSL** extension → **WSL: Open Folder** and open `/home/<you>/netscope_build`. On Windows Explorer you can also use `\\wsl$\Ubuntu\home\<you>\netscope_build`.

---

## CMakeLists.txt Content explanation

### `cmake_minimum_required(VERSION 3.16)`

Ensures the user runs CMake 3.16 or newer so all commands work as expected.

### `project(netscope_starter CXX)`

* Names your project `netscope_starter`.
* `CXX` declares you’re using C++ (so CMake sets C++ variables and toolchains).

### `set(CMAKE_CXX_STANDARD 17)`

Requests the C++ language standard: **C++17**.
(Same idea as passing `-std=c++17` to `g++`.)

### `set(CMAKE_CXX_STANDARD_REQUIRED ON)`

Makes the standard **strict**: don’t silently fall back to an older standard.

### `add_executable(decode_one src/decode_one.cpp)`

* Defines a target called `decode_one` of type **executable**.
* Tells CMake which source files belong to that target (`src/decode_one.cpp`).
* CMake then knows how to:

  1. compile that `.cpp` into an object file,
  2. link it into a binary named `decode_one`.

---

## Terms (quick networking glossary)

* **Ethernet dst/src:** local network addresses (MAC). Switches use these on your LAN.
* **`type=0x0800`:** the next layer is IPv4.
* **IPv4 src/dst:** internet addresses (who’s sending / who’s receiving). Routers use these.
* **`ttl=64`:** a hop limit so packets don’t loop forever.
* **`proto=6`:** the next layer is TCP (17 would mean UDP).
* **TCP src_port/dst_port:** which app on each side (54321 on your side → 80 on the server).
* **Flags:** `SYN` means “start”, `ACK` means “I received yours”, `FIN` means “finish”, `RST` means “reset/abort”.

---

## Next: create a capture file (PCAP) to read

**Commands to be run next:**

```bash
sudo apt update
sudo apt install -y libpcap-dev tcpdump
sudo tcpdump -D
sudo tcpdump -i any -c 100 '(tcp or udp) and not port 22' -w ~/sample.pcap
ls -lh ~/sample.pcap
```

**what each line does (brief)**

* `libpcap-dev` → headers/libs we’ll use to read pcap files in C++ later.
* `tcpdump` → a tiny tool to record packets into a `.pcap` file.
* `tcpdump -D` → shows available interfaces (just info).
* `tcpdump -i any -c 100 ... -w ~/sample.pcap`

  * `-i any` = listen on all interfaces in WSL
  * `-c 100` = stop after 100 packets (so it finishes quickly)
  * the filter keeps common traffic and ignores SSH
  * `-w ~/sample.pcap` = save to your home folder
* `ls -lh ~/sample.pcap` → confirm the file exists and size looks reasonable (tens of KB+).

> **Important tip:** Capturing with `-i any` in Linux uses **Linux Cooked Capture (SLL)** link type, not Ethernet. Our simple reader expects **Ethernet**. For readable output in the next step, capture on a specific interface (e.g., `eth0`) instead:
>
> ```bash
> ip -br link                     # list interfaces
> sudo tcpdump -i eth0 -c 120 '(tcp or udp) and not port 22' -w ~/sample_eth.pcap
> ```

---

## Add the PCAP reader (build a second tiny program)

Open your `CMakeLists.txt` and add these two lines to the end:

```cmake
add_executable(pcap_read src/pcap_read.cpp)
target_link_libraries(pcap_read PRIVATE pcap)
```

Back in WSL:

```bash
cmake /mnt/e/Coding-practice/Projects/NetScope
cmake --build . -j
```

then:

```bash
./pcap_read ~/sample.pcap        # if captured with -i any, may print few lines
./pcap_read ~/sample_eth.pcap    # recommended: capture from eth0 for Ethernet frames
```
Great job—your reader ran perfectly. The “Processed 94 packets.” with **no lines printed** is actually a clue about *how* the capture was taken. Here’s what happened and the next tiny step.

## Why you saw “Processed 94 packets” but no per-packet lines initally

* You captured using `tcpdump -i any ... -w sample.pcap`.
* On Linux/WSL, **`-i any` uses a special link layer** called **Linux Cooked Capture** (link type `DLT_LINUX_SLL`).
* Our code currently assumes **Ethernet** frames (14-byte Ethernet header). With SLL, the header layout is different, so our function returns early without printing.

So: the file *does* have 94 packets, but they’re SLL frames, not Ethernet frames; your decoder just doesn’t recognize that header yet.

### Quick way to confirm (optional)

In WSL:

```bash
file ~/sample.pcap
```

You’ll likely see: “… pcap capture file … link-type **LINUX_SLL** …”.

---

## What these “packets” are & who was talking

* A **packet** is a small “envelope” of data your system sent/received while `tcpdump` was recording.
* Since you recorded in WSL, these are mostly your **WSL instance** talking to:

  * local services (e.g., DNS resolver),
  * the Windows host or gateway (NAT),
  * external servers you contacted during the capture window (e.g., `curl`, `ping`, background updates).
* Because we filtered for `tcp or udp`, they’re mostly **TCP/UDP** packets (web, DNS, API calls, etc.).

We’ll *see* the actual IPs once we run our reader on an Ethernet capture.

---

## One tiny step: recapture as Ethernet (so your reader prints)

Let’s capture on a **specific interface** (Ethernet-like), not `any`.

1. See your interfaces:

```bash
ip -br link
```

You’ll see names like `lo` and `eth0`. We want `eth0`.

2. Capture 120 packets on `eth0`:

```bash
sudo tcpdump -i eth0 -c 120 '(tcp or udp) and not port 22' -w ~/sample_eth.pcap
```

Tip: while it runs, generate a bit of traffic in another terminal:

```bash
curl https://example.com
ping -c 3 8.8.8.8
```

3. Run your reader on the new file:

```bash
cd ~/netscope_build
./pcap_read ~/sample_eth.pcap
```

✅ You should now see lines like:

```
TCP  172.24.64.1:52344  ->  93.184.216.34:80  flags[SYN=1 ACK=0 FIN=0 RST=0]
UDP  172.24.64.1:56789  ->  1.1.1.1:53
...
Processed 120 packets.
```

**How to read that:**

* Left side = your WSL IP/port, right side = destination IP/port.
* `TCP flags` show handshake and connection state.
* `UDP` lines show things like DNS queries (port 53), etc.

---

---

## Additional tips / troubleshooting

* **“Processed N packets” but no lines printed:**
  Your capture might be **SLL** (from `-i any`), while the simple reader expects **Ethernet**. Re-capture from `eth0` as shown above.

* **VS Code says `cannot open source file pcap.h`:**
  That’s Windows IntelliSense. You’re compiling in WSL where `libpcap-dev` is installed. Use the **WSL extension** in VS Code and **Open Folder in WSL** so IntelliSense runs inside Ubuntu.

* **CMake errors on `/mnt/…` paths (Operation not permitted):**
  Generate and build in your Linux home (e.g., `~/netscope_build`) and point CMake at the Windows source path.

---

## Glossary (super short)

* **Packet**: a small chunk of data with *headers* (labels) and *payload* (content).
* **Ethernet**: local network label, includes MAC addresses.
* **IP (IPv4)**: internet label, includes source/destination IP addresses.
* **TCP**: connection label, includes ports and *flags* like SYN (start) and ACK (acknowledge).
* **Big-endian**: the order used on the network; we convert numbers with `ntohs`/`ntohl` so they print correctly.

---
