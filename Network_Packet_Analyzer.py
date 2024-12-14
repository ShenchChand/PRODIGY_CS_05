from scapy.all import sniff, wrpcap, IP, TCP, UDP

packets = []  # List to store captured packets

def process_packet(packet):
    global packets
    try:
        # Check if packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            # Determine protocol type
            if proto == 6:  # TCP
                protocol = "TCP"
            elif proto == 17:  # UDP
                protocol = "UDP"
            else:
                protocol = "Other"

            # Print captured packet details
            print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")

            # Print payload data if present
            if TCP in packet or UDP in packet:
                payload = bytes(packet[TCP].payload or packet[UDP].payload)
                if payload:
                    print(f"Payload: {payload[:50]}..." if len(payload) > 50 else f"Payload: {payload}")

            packets.append(packet)  # Store packet in the list

    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniff packets with optional customization
def start_sniffing(filter_option="ip", packet_count=0):
    global packets
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(filter=filter_option, prn=process_packet, store=False, count=packet_count)

if __name__ == "__main__":
    print("Welcome to the Packet Sniffer Tool")
    print("You can customize the following options:")
    print("1. Packet Filter (e.g., 'tcp', 'udp', 'host 192.168.1.1')")
    print("2. Number of Packets to Capture (0 for unlimited)")

    # Get user input for customization
    filter_option = input("Enter packet filter (default 'ip'): ") or "ip"
    packet_count = input("Enter number of packets to capture (default 0 for unlimited): ")

    try:
        packet_count = int(packet_count)
    except ValueError:
        print("Invalid number of packets. Using default (0).")
        packet_count = 0

    # Start sniffing with user options
    start_sniffing(filter_option=filter_option, packet_count=packet_count)

    # Post-sniffing options
    print("\nPacket capture complete.")
    while True:
        print("\nChoose an option:")
        print("1. Save captured packets to a .pcap file")
        print("2. Restart packet capture")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            file_name = input("Enter the file name to save packets (e.g., 'capture.pcap'): ") or "capture.pcap"
            wrpcap(file_name, packets)
            print(f"Packets saved to {file_name}. The file is stored in the current working directory.")
        elif choice == "2":
            print("Restarting packet capture...")
            packets.clear()  # Clear the stored packets
            start_sniffing(filter_option=filter_option, packet_count=packet_count)
        elif choice == "3":
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
