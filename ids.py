import logging
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Initialize logging
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Track suspicious activity
port_scan_threshold = 10
traffic_threshold = 100
scan_interval = 10
traffic_interval = 60

port_scans = defaultdict(list)
high_traffic = defaultdict(list)

def detect_port_scan(ip_src):
    current_time = time.time()
    port_scans[ip_src] = [timestamp for timestamp in port_scans[ip_src] if current_time - timestamp < scan_interval]
    port_scans[ip_src].append(current_time)
    if len(port_scans[ip_src]) > port_scan_threshold:
        logging.warning(f"Port scan detected from {ip_src}")
        print(f"Port scan detected from {ip_src}")

def detect_high_traffic(ip_src):
    current_time = time.time()
    high_traffic[ip_src] = [timestamp for timestamp in high_traffic[ip_src] if current_time - timestamp < traffic_interval]
    high_traffic[ip_src].append(current_time)
    if len(high_traffic[ip_src]) > traffic_threshold:
        logging.warning(f"High traffic detected from {ip_src}")
        print(f"High traffic detected from {ip_src}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            detect_port_scan(ip_src)
            detect_high_traffic(ip_src)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            detect_high_traffic(ip_src)
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst}")

def main():
    interface = 'en0'  # Specify your interface here
    print(f"Starting IDS on interface: {interface}")
    sniff(prn=packet_callback, iface=interface)

if __name__ == "__main__":
    main()