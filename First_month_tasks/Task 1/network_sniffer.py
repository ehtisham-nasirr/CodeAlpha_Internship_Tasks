
from scapy.all import sniff, IP, TCP, UDP

# Function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
        else:
            print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

# Sniffing the network
print("Starting network sniffer...")
sniff(prn=analyze_packet, filter="ip", count=10)
