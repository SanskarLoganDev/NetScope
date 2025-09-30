To make the directory in root:
mkdir -p ~/netscope_build 

cmake /mnt/e/Coding-practice/Projects/NetScope
cmake --build . -j

To start listening
./pcap_read ~/sample_eth.pcap