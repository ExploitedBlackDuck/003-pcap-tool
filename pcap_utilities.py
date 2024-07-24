import logging
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, ICMP, Raw, Dot11
import re
from datetime import datetime
import ipaddress

def combine_pcaps(input_files, output_file):
    try:
        packets = []
        for file in input_files:
            packets.extend(rdpcap(file))
        wrpcap(output_file, packets)
        logging.info(f"Combined pcap files {input_files} into {output_file}")
    except Exception as e:
        logging.error(f"Error combining pcap files: {e}")
        print(f"Error combining pcap files: {e}")

def split_pcap(input_file, output_prefix):
    try:
        packets = rdpcap(input_file)
        for i, packet in enumerate(packets):
            wrpcap(f"{output_prefix}_{i}.pcap", [packet])
        logging.info(f"Split pcap file {input_file} into multiple files with prefix {output_prefix}")
    except Exception as e:
        logging.error(f"Error splitting pcap file: {e}")
        print(f"Error splitting pcap file: {e}")

def detect_anomalies(input_file):
    try:
        packets = rdpcap(input_file)
        anomalies = []
        for packet in packets:
            if len(packet) > 1500:
                anomalies.append(packet)
        if anomalies:
            print(f"Detected {len(anomalies)} anomalies in {input_file}")
            logging.info(f"Detected {len(anomalies)} anomalies in {input_file}")
        else:
            print("No anomalies detected.")
            logging.info(f"No anomalies detected in {input_file}")
    except Exception as e:
        logging.error(f"Error detecting anomalies: {e}")
        print(f"Error detecting anomalies: {e}")

def filter_packets(input_file, filters):
    try:
        packets = rdpcap(input_file)
        filtered_packets = []
        for packet in packets:
            if match_filters(packet, filters):
                filtered_packets.append(packet)
        logging.info(f"Filtered packets in {input_file} with filters {filters}")
        return filtered_packets
    except Exception as e:
        logging.error(f"Error filtering packets: {e}")
        print(f"Error filtering packets: {e}")
        return []

def match_filters(packet, filters):
    if 'src_ip' in filters and packet.haslayer(IP) and packet[IP].src != filters['src_ip']:
        return False
    if 'dst_ip' in filters and packet.haslayer(IP) and packet[IP].dst != filters['dst_ip']:
        return False
    if 'src_subnet' in filters and packet.haslayer(IP):
        if ipaddress.ip_address(packet[IP].src) not in ipaddress.ip_network(filters['src_subnet']):
            return False
    if 'dst_subnet' in filters and packet.haslayer(IP):
        if ipaddress.ip_address(packet[IP].dst) not in ipaddress.ip_network(filters['dst_subnet']):
            return False
    if 'src_port' in filters and packet.haslayer(TCP) and packet[TCP].sport != filters['src_port']:
        return False
    if 'dst_port' in filters and packet.haslayer(TCP) and packet[TCP].dport != filters['dst_port']:
        return False
    if 'protocol' in filters:
        if filters['protocol'].lower() == 'tcp' and not packet.haslayer(TCP):
            return False
        elif filters['protocol'].lower() == 'udp' and not packet.haslayer(UDP):
            return False
        elif filters['protocol'].lower() == 'icmp' and not packet.haslayer(ICMP):
            return False
    if 'tcp_flags' in filters and packet.haslayer(TCP):
        flags = filters['tcp_flags'].lower()
        packet_flags = str(packet[TCP].flags).lower()
        if not all(flag in packet_flags for flag in flags):
            return False
    if 'mac_oui' in filters and packet.haslayer(Dot11) and not packet[Dot11].addr2.startswith(filters['mac_oui']):
        return False
    if 'http_request' in filters and packet.haslayer(Raw):
        if not re.search(filters['http_request'], str(packet[Raw].load), re.IGNORECASE):
            return False
    if 'url' in filters and packet.haslayer(Raw):
        if not re.search(filters['url'], str(packet[Raw].load), re.IGNORECASE):
            return False
    if 'date' in filters or 'time' in filters:
        pkt_time = datetime.fromtimestamp(packet.time)
        if 'date' in filters and filters['date'] != pkt_time.strftime('%Y-%m-%d'):
            return False
        if 'time' in filters and filters['time'] != pkt_time.strftime('%H:%M:%S'):
            return False
    return True
