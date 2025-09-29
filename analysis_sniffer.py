# analysis_sniffer.py
from scapy.all import rdpcap, IP, TCP, UDP
import sys
from collections import Counter

pcap = "capture.pcap"
if len(sys.argv) > 1:
    pcap = sys.argv[1]

try:
    packets = rdpcap(pcap)
except Exception as e:
    print("Cannot read pcap:", e)
    sys.exit(1)

counts = Counter()
for p in packets:
    if IP in p:
        if TCP in p:
            counts['TCP'] += 1
        elif UDP in p:
            counts['UDP'] += 1
        else:
            counts['OTHER_IP'] += 1
    else:
        counts['NON_IP'] += 1

print("Packet counts from", pcap)
for k,v in counts.items():
    print(f"{k}: {v}")
