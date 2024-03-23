from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload
            
            print(f"TCP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
            print(f"Payload: {payload}")
        
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = packet[UDP].payload
            
            print(f"UDP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
            print(f"Payload: {payload}")

# Start sniffing packets
print("Packet Sniffer started...")
sniff(prn=packet_callback, store=0)
