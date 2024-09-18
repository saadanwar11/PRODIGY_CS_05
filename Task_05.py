from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to analyze and print details of each captured packet
def packet_analysis(packet):
    if IP in packet:  # Check if the packet has an IP layer
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for TCP
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        
        # Check for UDP
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        # Check for ICMP
        elif ICMP in packet:
            print(f"ICMP Type: {packet[ICMP].type}")

        # Display packet payload (if available)
        if packet[IP].payload:
            print(f"Payload: {bytes(packet[IP].payload)[:50]}...")  # Print first 50 bytes of payload

# Function to start the packet sniffer
def start_sniffing(interface=None):
    print(f"[*] Starting packet capture on {interface if interface else 'all interfaces'}")
    # Sniff packets on the specified interface (or all interfaces if none is provided)
    sniff(iface=interface, prn=packet_analysis, store=False)

# Main program
if __name__ == "__main__":
    # Optionally set an interface (like 'eth0', 'wlan0') to sniff on, or None for all interfaces
    interface = None
    start_sniffing(interface)
