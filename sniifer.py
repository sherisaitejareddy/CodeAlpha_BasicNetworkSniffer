from scapy.all import sniff, IP, TCP, UDP, Raw
import csv

# File to save results
OUTPUT_FILE = "packets_log.csv"

# Initialize CSV with headers
with open(OUTPUT_FILE, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Payload"])

def packet_callback(packet):
    src_ip = dst_ip = proto = sport = dport = payload = "N/A"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")
            except:
                payload = str(packet[Raw].load)

        # Print to console
        print(f"\n[+] Packet Captured:")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")
        print(f"Source Port: {sport}, Destination Port: {dport}")
        print(f"Payload: {payload[:50]}...")

        # Save to CSV
        with open(OUTPUT_FILE, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([src_ip, dst_ip, proto, sport, dport, payload[:200]])  # limit payload

print("Starting network sniffer... (press Ctrl+C to stop)")
# Capture indefinitely (remove count to run continuously)
sniff(prn=packet_callback, store=False)
