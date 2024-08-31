# WinShark

WinShark is a powerful, CLI-based network packet capture and analysis tool for Windows. Inspired by Wireshark, it allows users to capture, analyze, and even inject packets on their network interfaces. This tool is designed for network professionals, ethical hackers, and anyone interested in deep network analysis.

## Features

- **Network Interface Listing**: List all available network interfaces.
- **Packet Capture**: Capture packets on a specified interface with optional filters.
- **Advanced Filtering**: Apply BPF filters during capture and PyShark display filters during analysis.
- **Packet Injection**: Inject custom packets with specified source and destination IPs/ports.
- **PCAP File Analysis**: Read and analyze PCAP files using PyShark.
- **Logging**: Detailed logging of all activities and captured data.
- **Firewall Bypass**: Automatically attempts to bypass firewalls when capturing packets (for ethical use).

## Installation

### Requirements

- Python 3.7+
- Windows OS
- [Scapy](https://scapy.net/)
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Pcapy](https://pypi.org/project/pcapy/) or [Pylibpcap](https://github.com/riobard/pylibpcap) (for alternative)

### Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/WinShark.git
   cd WinShark

2. **Run it**

   ```bash
   python winshark.py --help
   ```
### CREDIT:
Quy Anh Nguyen - Developer
