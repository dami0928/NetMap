<div style="text-align:center;">
  <img src="./assets/banner.jpg" alt="Banner" style="width:100%; height:auto;" />
</div>

# Network Scanner

**Author:** Damiano Gubiani  
**Version:** 1.0 

A high-quality port scanner developed in Python using the Scapy library, designed for comprehensive network reconnaissance and security assessments.

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

## purpose

Designed for **ethical hacking** and **network assessment**, this tool enhances security testing capabilities while maintaining a **low profile** in monitored environments.

## Installation

To install the network scanner, clone this repository and install the required dependencies:

```bash
git clone https://github.com/dami0928/NetMap.git
cd NetMap
pip install -r requirements.txt
```
