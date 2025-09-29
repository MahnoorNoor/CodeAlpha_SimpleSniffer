# simple_sniffer.py
# Basic packet sniffer using scapy
import sys
import time
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap

def packet_callback(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto_name = "OTHER"
        if TCP in pkt:
            proto_name = "TCP"
        elif UDP in pkt:
            proto_name = "UDP"
        payload = ""
        if Raw in pkt:
            raw_bytes = bytes(pkt[Raw].load)
            payload = raw_bytes[:100].decode('utf-8', errors='replace')
        print(f"[{time.strftime('%H:%M:%S')}] {src} -> {dst} | {proto_name} | payload: {payload}")

def main():
    iface = None
    count = 0
    timeout = None
    out_pcap = None

    # simple CLI args:
    # python simple_sniffer.py            -> sniff forever (needs Ctrl+C)
    # python simple_sniffer.py 10         -> capture 10 packets
    # python simple_sniffer.py 10 eth0    -> capture 10 packets on eth0
    # python simple_sniffer.py 0 eth0 out.pcap -> capture until Ctrl+C and save to out.pcap
    args = sys.argv[1:]
    if len(args) >= 1:
        try:
            count = int(args[0])
        except:
            count = 0
    if len(args) >= 2:
        iface = args[1]
    if len(args) >= 3:
        out_pcap = args[2]

    print("Starting sniffer...")
    if iface:
        print(f"Interface: {iface}")
    if count > 0:
        print(f"Packet count: {count}")
    if out_pcap:
        print(f"Will save capture to: {out_pcap}")

    captured = []
    try:
        # sniff returns a PacketList you can save with wrpcap()
        pkts = sniff(count=count if count>0 else 0, iface=iface, prn=packet_callback, store=True, timeout=timeout)
        captured = pkts
    except PermissionError:
        print("Permission denied: run this script with sudo / Administrator privileges.")
        return
    except Exception as e:
        print("Sniffer error:", e)
        return

    if out_pcap and len(captured) > 0:
        try:
            wrpcap(out_pcap, captured)
            print(f"Saved {len(captured)} packets to {out_pcap}")
        except Exception as e:
            print("Error saving pcap:", e)

if __name__ == "__main__":
    main()
