To make the directory in root:
mkdir -p ~/netscope_build 

cmake /mnt/e/Coding-practice/Projects/NetScope
cmake --build . -j

To start listening
# See your interfaces (eth0 is what we want in WSL2)
ip -br link

# Capture ~200 TCP/UDP packets on eth0 and save to a new file
sudo tcpdump -i eth0 -c 200 '(tcp or udp) and not port 22' -w ~/fresh_eth.pcap
./pcap_read ~/sample_eth.pcap

# Analyze the packet
cd ~/netscope_build
./netscope_cli ~/fresh_eth.pcap --verbose   # see per-packet lines
./netscope_cli ~/fresh_eth.pcap             # summary only

# summary-only (default)
./netscope_cli ~/fresh_eth.pcap

# with per-packet lines
./netscope_cli ~/fresh_eth.pcap --verbose

# top 5 rows instead of 3
./netscope_cli ~/fresh_eth.pcap --top 5
