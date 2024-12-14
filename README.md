### Description 
A packet sniffer tool that captures and analyzes network packets and display relevant information such as source and destination IP addresses, protocols, and payload data.

## Requirements: 
Install Scapy: Ensure you have the Scapy library installed. Use the command:

    pip install scapy

This tool requires elevated privileges to capture packets. Run the script with sudo or as an administrator

    sudo python3 Network_Packet_Analyzer.py
    
Run the Script:

When the script starts, you will see options to enter a packet filter and a number of packets to capture.

    Examples:
        Filter: Enter tcp, udp, or host 192.168.1.1 (or press Enter to use ip as the default).
        Number of packets: Enter 10 (or press Enter for unlimited).
Capture Packets:

        The script will start sniffing traffic and display details about each captured packet (source, destination, protocol, and payload).
Save Packets:

    After stopping the capture (Ctrl+C), choose the option to save packets:
        Enter 1 to save packets to a .pcap file.
        Specify the filename (e.g., capture.pcap).
    The file will be saved in the directory where the script is located.
Open the .pcap File:

    Use Wireshark or similar tools to view the captured packets.
        Install Wireshark: https://www.wireshark.org/
        Open the saved .pcap file for detailed analysis.

### Use this tool strictly for learning or troubleshooting in environments where you have permission to monitor network traffic. Unauthorized use may violate privacy laws or policies.
        
