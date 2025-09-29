## Task 1 - Basic Network Sniffer

Files:
- simple_sniffer.py      : Python sniffer (scapy)
- sniff_output.txt       : Sample console output
- capture.pcap           : Packet capture (optional)
- analysis_sniffer.py    : Small script that summarizes protocols
- sniffer_analysis.txt   : Result of analysis
How to run:
- Install scapy: sudo python3 -m pip install scapy
- Run: sudo python3 simple_sniffer.py 50 > sniff_output.txt
- Optional save: sudo python3 simple_sniffer.py 0 wlan0 capture.pcap
