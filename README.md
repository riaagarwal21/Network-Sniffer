# Network-Sniffer
A complete Python-based network sniffer with logging, GeoIP, threat detection, SQLite, and data visualization — built for real-time network diagnostics and security analysis.

---

## 📜 Description

This project captures real-time network packets and provides detailed insights into:
- Source/destination IPs
- Protocols (TCP, UDP, ARP, ICMP)
- DNS/HTTP layer data
- Geolocation of source IPs using MaxMind GeoIP2
- Potential threats like ARP spoofing and SYN floods

It uses a multi-threaded approach to keep capture and processing efficient and writes data to a log file, SQLite database, and optionally a `.pcap` file viewable in Wireshark.

---

## 🚀 Features

- 📡 **Real-time packet capture** using Scapy
- 🌍 **GeoIP lookup** for external IPs using MaxMind GeoLite2
- 🔐 **Threat detection**:
  - ARP spoofing detection (fake MACs)
  - SYN flood or port scan alerts
- 🧠 **Protocol parsing** for:
  - TCP, UDP, ICMP, ARP
  - DNS queries
  - HTTP request host headers
- 🗂️ **Logs** all data to:
  - `sniffer_log.txt` (text file)
  - `packets.db` (SQLite database)
- 📊 **Data visualization**:
  - Pie chart: Protocol distribution
  - Bar chart: Top 5 IP addresses
- 📦 **Output `.pcap` file** compatible with Wireshark
- ⚡ Multithreaded processing using `Queue` and `Thread`
- 🧪 Modular code for easy feature extension

---

## 📦 Requirements

- Python 3.6 or higher
- Packages:
  - `scapy`
  - `geoip2`
  - `matplotlib`
  - `sqlite3` (built-in)

### Install dependencies

```bash
pip3 install scapy geoip2 matplotlib
```
---

## ⚙️ Installation

```bash
git clone https://github.com/riaagarwal21/Network-Sniffer.git
```

### 🌍 Setting Up GeoIP Database

This tool uses MaxMind's GeoLite2 database for IP location detection.
- Create an account on https://www.maxmind.com
- Download `GeoLite2-City (free)`
- Extract the `.mmdb` file and rename it to `GeoLite2-City.mmdb`
- Place the file in the same folder as the `network_sniffer.py`

### 🔐 Setting Your Trusted MAC Address (ARP Spoof Protection)

Replace the value of `knownMac` variable in `detectThreats()` function with the string containing the MAC address of your router/gateway

### To Run

Replace the placeholders:
- `<interface>`  : your active network interface
- `<filter>`     : optional BPF filter
- `<seconds>`    : duration of capture in seconds
- `<output.pcap>`: optional files to save captured packets for Wireshark
  
```bash
sudo -E python3 network_sniffer.py -i <interface> -f "<filter>" -t <seconds> -o <output.pcap>
```

---

## 📊 Visualizations

At the end of the run, `network_stats.png` is generated, which contains:
- 📈 Pie chart of protocol breakdown (TCP/UDP/ARP/etc.)
- 📊 Bar chart of top 5 source IPs by packet count

To view:
```bash
xdg-open network_stats.png
```
![network_stats](https://github.com/user-attachments/assets/d2d09e36-ce4e-43e1-a483-72068ce9b1aa)

---

## ⚠️ Disclaimer

This tool is meant only for educational and authorized use.
Do not run this on networks without permission — doing so may violate laws or terms of service.

---
> 📌 Created with ❤️ by Ria Agarwal
