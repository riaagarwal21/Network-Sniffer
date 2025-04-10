import smtplib
import argparse
import sqlite3
import threading
import geoip2.database
from queue import Queue
from threading import Thread
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter
from scapy.layers.http import HTTPRequest
from scapy.all import sniff, IP, TCP, UDP, ARP, DNSQR, ICMP, wrpcap

# Configuration
LOG_FILE = "sniffer_log.txt"
PCAP_FILE = "capture.pcap"
GEOIP_DB = "GeoLite2-City.mmdb"
SQLITE_DB = "packets.db"

# Global statistics
Stats = {
    "TotalPackets": 0,
    "Protocols": Counter(),
    "TopIPs": Counter(),
    "Alerts": []
}

# Initialize GeoIP
try:
    GeoIPReader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    GeoIPReader = None

# Create SQLite table
def initDatabase():
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            port INTEGER,
            info TEXT,
            location TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Logging function
def logPacket(packetInfo, srcIP, dstIP, protocol, port, location=None):
    with open(LOG_FILE, "a") as f:
        f.write(packetInfo + "\n")

    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, port, info, location)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (str(datetime.now()), srcIP, dstIP, protocol, port, packetInfo, location))
    conn.commit()
    conn.close()

# Alert
def sendAlert(subject, message):
    alertMessage = f"[ALERT] {subject}: {message}"
    print(alertMessage)

# GeoIP lookup
def getLocation(ip):
    if not GeoIPReader:
        return None
    try:
        response = GeoIPReader.city(ip)
        return f"{response.country.name}, {response.city.name}"
    except:
        return None

# Detect threats
def detectThreats(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        knownMac = ""  # Replace with trusted MAC
        if packet[ARP].hwsrc != knownMac:
            alert = f"ARP Spoofing detected! Fake MAC: {packet[ARP].hwsrc}"
            Stats["Alerts"].append(alert)
            sendAlert("ARP Spoof Alert", alert)

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        if Stats["TotalPackets"] % 100 == 0 and Stats["Protocols"]["TCP_SYN"] > 50:
            alert = "Possible SYN Flood/Port Scan detected!"
            Stats["Alerts"].append(alert)
            sendAlert("SYN Flood Alert", alert)

# Analyze each packet
def processPacket(packet):
    Stats["TotalPackets"] += 1
    packetInfo = ""
    srcIP = dstIP = protocol = port = location = None

    if packet.haslayer(IP):
        ipLayer = packet[IP]
        srcIP = ipLayer.src
        dstIP = ipLayer.dst
        protocol = ipLayer.proto
        location = getLocation(srcIP)

        packetInfo = f"{datetime.now()} | {srcIP} -> {dstIP} | Protocol: {protocol}"
        Stats["TopIPs"].update([srcIP])

        if packet.haslayer(TCP):
            tcpLayer = packet[TCP]
            port = tcpLayer.dport
            packetInfo += f" | TCP Port: {port}"
            Stats["Protocols"].update(["TCP"])
            if port == 80 and packet.haslayer(HTTPRequest):
                try:
                    host = packet[HTTPRequest].Host.decode()
                    packetInfo += f" | HTTP Host: {host}"
                except:
                    pass
            if tcpLayer.flags == "S":
                Stats["Protocols"].update(["TCP_SYN"])

        elif packet.haslayer(UDP):
            udpLayer = packet[UDP]
            port = udpLayer.dport
            packetInfo += f" | UDP Port: {port}"
            Stats["Protocols"].update(["UDP"])
            if port == 53 and packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR].qname.decode('utf-8')
                    packetInfo += f" | DNS Query: {query}"
                except:
                    pass

        elif packet.haslayer(ICMP):
            packetInfo += " | ICMP"
            Stats["Protocols"].update(["ICMP"])

        elif packet.haslayer(ARP):
            packetInfo += " | ARP"
            Stats["Protocols"].update(["ARP"])

        if location:
            packetInfo += f" | Location: {location}"

        print(packetInfo)
        logPacket(packetInfo, srcIP, dstIP, protocol, port, location)
        detectThreats(packet)

# Plot stats
def plotStats():
    plt.figure(figsize=(12, 6))

    plt.subplot(1, 2, 1)
    plt.pie(
        [Stats["Protocols"][p] for p in Stats["Protocols"] if p != "TCP_SYN"],
        labels=[p for p in Stats["Protocols"] if p != "TCP_SYN"],
        autopct="%1.1f%%"
    )
    plt.title("Protocol Distribution")

    plt.subplot(1, 2, 2)
    topIPs = Stats["TopIPs"].most_common(5)
    plt.bar([ip[0] for ip in topIPs], [ip[1] for ip in topIPs])
    plt.title("Top 5 Source IPs")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("network_stats.png")
    print("[+] Saved stats to network_stats.png")

# Threaded packet handling
PacketQueue = Queue()

def snifferThread(interface, filterExp):
    sniff(iface=interface, filter=filterExp, prn=lambda x: PacketQueue.put(x), store=0)

def analyzerThread():
    while True:
        packet = PacketQueue.get()
        processPacket(packet)

# Main
def main():
    parser = argparse.ArgumentParser(description="Advanced Python Network Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, default="eth0", help="Network interface")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter")
    parser.add_argument("-t", "--time", type=int, default=0, help="Duration in seconds (0 = infinite)")
    parser.add_argument("-o", "--output", type=str, help="PCAP output file")
    args = parser.parse_args()

    initDatabase()
    print(f"[*] Starting sniffer on {args.interface}...")

    Thread(target=snifferThread, args=(args.interface, args.filter)).start()
    Thread(target=analyzerThread).start()

    try:
        if args.time > 0:
            print(f"[*] Running for {args.time} seconds...")
            threading.Event().wait(args.time)
        else:
            while True:
                threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")

    if args.output:
        print(f"[*] Saving packets to {args.output}")
        packets = list(PacketQueue.queue)
        wrpcap(args.output, packets)

    plotStats()
    print(f"[+] Packets captured: {Stats['TotalPackets']}")
    print(f"[+] Protocol breakdown: {dict(Stats['Protocols'])}")
    if Stats['Alerts']:
        print("\n[!] Security Alerts:")
        for alert in Stats["Alerts"]:
            print(f" - {alert}")

main()
