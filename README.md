<div style="text-align:center;">
  <img src="./banner.jpg" alt="Banner" style="width:100%; height:auto;" />
</div>

# Network Scanner

**Author:** Damiano Gubiani  
**Version:** 1.0 

A powerful network scanner designed to perform advanced network discovery and scanning techniques while incorporating features for IDS evasion and firewall detection.

## Features

- **Host Discovery**: Identify live hosts on a network using various techniques, including:
  - ARP ping
  - ICMP echo requests
  - TCP SYN scanning

- **Scanning Techniques**:
  - TCP Connect Scan
  - SYN Scan (Stealth Scan)
  - UDP Scan
  - FIN Scan
  - NULL Scan

- **IDS Evasion**: 
  - Fragmentation of packets
  - Slow scanning techniques to avoid detection

- **Firewall Detection**:
  - Analyze response behavior to identify firewall configurations
  - Support for OS fingerprinting to determine device types behind firewalls

## Installation

To install the network scanner, clone this repository and install the required dependencies:

```bash
git clone https://github.com/dami0928/NetMap.git
cd network-scanner
pip install -r requirements.txt
```
