import time
import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest  # Import HTTP packet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids.log"),
        logging.StreamHandler()
    ]
)

high_traffic = {}
traffic_threshold = 10  # Example threshold

def detect_port_scan(ip_src):
    logging.warning(f"Port scan detected from {ip_src}")
    logging.info(f"Port scan detected from {ip_src}")

def detect_high_traffic(ip_src):
    current_time = time.time()
    if ip_src not in high_traffic:
        high_traffic[ip_src] = []
    high_traffic[ip_src] = [timestamp for timestamp in high_traffic[ip_src] if current_time - timestamp < 60]
    high_traffic[ip_src].append(current_time)
    if len(high_traffic[ip_src]) > traffic_threshold:
        logging.warning(f"High traffic detected from {ip_src}")
        logging.info(f"High traffic detected from {ip_src}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Ignore traffic from 10.0.0.190
        if ip_src == '10.0.0.190':
            return

        protocol = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            logging.info(f"TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            detect_port_scan(ip_src)
            detect_high_traffic(ip_src)
            
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            logging.info(f"UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            detect_high_traffic(ip_src)
        
        # Check for HTTP requests
        if packet.haslayer(HTTPRequest):
            http_layer = packet.getlayer(HTTPRequest)
            host = http_layer.Host.decode() if http_layer.Host else "Unknown"
            path = http_layer.Path.decode() if http_layer.Path else "Unknown"
            method = http_layer.Method.decode() if http_layer.Method else "Unknown"
            logging.info(f"HTTP Request: {method} {host}{path} from {ip_src}")
        
        # Print raw data if present
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                decoded_data = raw_data.decode('utf-8')
                logging.info(f"Raw data (decoded): {decoded_data}")
            except UnicodeDecodeError:
                logging.info(f"Raw data (binary): {raw_data}")

sniff(filter="ip", prn=packet_callback, store=0)