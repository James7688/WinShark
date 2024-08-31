import argparse
from scapy.all import sniff, wrpcap, get_if_list, sendp
from scapy.layers.inet import IP, TCP, UDP
import pyshark
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def packet_callback(packet):
    # Advanced packet callback for more detailed analysis
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        payload_size = len(packet[IP].payload)

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol = "Other"
            sport = None
            dport = None

        logging.info(f"[{protocol}] {ip_src}:{sport} -> {ip_dst}:{dport} | Payload Size: {payload_size} bytes")


def capture_packets(interface, output_file=None, count=0, filters=None, display_filter=None):
    logging.info(f"Starting packet capture on {interface}...")

    try:
        packets = sniff(iface=interface, count=count, filter=filters, prn=packet_callback)

        if output_file:
            wrpcap(output_file, packets)
            logging.info(f"Packets saved to {output_file}")
        else:
            logging.info(f"Captured {len(packets)} packets")
    except PermissionError:
        logging.error("Permission denied. Ensure you have the necessary privileges or try running as administrator.")
    except OSError as e:
        logging.error(f"Error: {e}")
        logging.info(
            "It seems the connection is being blocked or filtered by a firewall. Attempting an alternative method...")
        alternative_capture(interface)


def alternative_capture(interface):
    logging.info("Trying an alternative capture method using port 443 (HTTPS)...")
    try:
        sniff(iface=interface, filter="tcp port 443", prn=packet_callback)
    except Exception as e:
        logging.error(f"Alternative method failed: {e}")


def analyze_packet_capture(file_path, filters=None):
    logging.info(f"Reading pcap file {file_path} with filters: {filters}")
    try:
        capture = pyshark.FileCapture(file_path, display_filter=filters)
        for packet in capture:
            logging.info(f"Packet Number: {packet.number} | Length: {packet.length} | Info: {packet}")
    except Exception as e:
        logging.error(f"Failed to analyze pcap file: {e}")


def inject_packet(interface, src_ip, dst_ip, src_port, dst_port, message):
    logging.info(f"Injecting packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} on {interface}")
    try:
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / message
        sendp(packet, iface=interface, verbose=False)
        logging.info("Packet injected successfully")
    except Exception as e:
        logging.error(f"Failed to inject packet: {e}")


def list_interfaces():
    interfaces = get_if_list()
    logging.info("Available network interfaces:")
    for iface in interfaces:
        logging.info(f"- {iface}")


def main():
    parser = argparse.ArgumentParser(
        description="WinShark Advanced: A powerful packet capture and analysis tool for Windows.",
        epilog="""
        Examples:

        # List available network interfaces:
        python winshark.py interfaces

        # Capture 100 packets on the 'Ethernet' interface, and save to output.pcap:
        python winshark.py capture -i Ethernet -o output.pcap -c 100

        # Capture packets on the 'Ethernet' interface with a filter for TCP traffic on port 80:
        python winshark.py capture -i Ethernet -f "tcp port 80"

        # Read and analyze a pcap file with a filter for HTTP traffic:
        python winshark.py read output.pcap -f "http"

        # Inject a TCP packet with custom message:
        python winshark.py inject -i Ethernet --src_ip 192.168.1.100 --dst_ip 192.168.1.1 --src_port 12345 --dst_port 80 --message "Hello, World!"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command')

    # Command to list interfaces
    parser_list = subparsers.add_parser('interfaces', help='List network interfaces')

    # Command to capture packets
    parser_capture = subparsers.add_parser('capture', help='Capture packets')
    parser_capture.add_argument('-i', '--interface', required=True, help='Network interface to capture on')
    parser_capture.add_argument('-o', '--output', help='Output file to save captured packets')
    parser_capture.add_argument('-c', '--count', type=int, default=0,
                                help='Number of packets to capture (0 for unlimited)')
    parser_capture.add_argument('-f', '--filter', help='BPF filter to apply during capture')
    parser_capture.add_argument('-d', '--display_filter', help='PyShark display filter for advanced analysis')

    # Command to read and analyze pcap file
    parser_read = subparsers.add_parser('read', help='Read and analyze a pcap file')
    parser_read.add_argument('file', help='Path to the pcap file')
    parser_read.add_argument('-f', '--filter', help='Display filter to apply during analysis')

    # Command to inject a custom packet
    parser_inject = subparsers.add_parser('inject', help='Inject a custom packet')
    parser_inject.add_argument('-i', '--interface', required=True, help='Network interface to inject packet on')
    parser_inject.add_argument('--src_ip', required=True, help='Source IP address')
    parser_inject.add_argument('--dst_ip', required=True, help='Destination IP address')
    parser_inject.add_argument('--src_port', type=int, required=True, help='Source port')
    parser_inject.add_argument('--dst_port', type=int, required=True, help='Destination port')
    parser_inject.add_argument('--message', required=True, help='Message to send in the packet')

    args = parser.parse_args()

    if args.command == 'interfaces':
        list_interfaces()

    elif args.command == 'capture':
        capture_packets(
            args.interface,
            output_file=args.output,
            count=args.count,
            filters=args.filter,
            display_filter=args.display_filter
        )

    elif args.command == 'read':
        analyze_packet_capture(args.file, filters=args.filter)

    elif args.command == 'inject':
        inject_packet(
            args.interface,
            args.src_ip,
            args.dst_ip,
            args.src_port,
            args.dst_port,
            args.message
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
