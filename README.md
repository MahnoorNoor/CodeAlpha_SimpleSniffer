# 🚀 Task 1 - Basic Network Sniffer

A simple **Python-based packet sniffer** that captures and analyzes network traffic using [Scapy](https://scapy.net/).  
This task demonstrates how data flows through the network, focusing on source/destination IPs, protocols, and payloads.

---

## 📂 Project Files

| File | Description |
|------|-------------|
| `simple_sniffer.py` | Main Python sniffer script (Scapy-based). |
| `sniff_output.txt` | Sample console output from a sniffing session. |
| `capture.pcap` | (Optional) Saved packet capture file (open in Wireshark). |
| `analysis_sniffer.py` | Script to summarize captured traffic by protocol. |
| `sniffer_analysis.txt` | Result of the analysis script (protocol counts). |

---

## ⚙️ How to Run

### 1. Install Requirements
Scapy is required for packet sniffing.  
On **Kali/Linux**:
```bash
sudo apt update
sudo apt install python3-scapy
