import argparse
import logging
from pcap_utilities import combine_pcaps, split_pcap, detect_anomalies, filter_packets

def setup_logging():
    logging.basicConfig(filename='pcap_tool.log', level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s:%(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description="PCAP File Tool")
    parser.add_argument('--combine', nargs='+', help="Combine multiple pcap files into one. Usage: --combine file1.pcap file2.pcap ... output.pcap")
    parser.add_argument('--split', help="Split a pcap file into multiple files. Usage: --split input.pcap output_prefix", nargs=2, metavar=('input_file', 'output_prefix'))
    parser.add_argument('--analyze', help="Analyze a pcap file for anomalies. Usage: --analyze input.pcap", metavar='input_file')
    parser.add_argument('--filter', help="Filter packets based on criteria. Usage: --filter input.pcap output.pcap", nargs=2, metavar=('input_file', 'output_file'))

    # Add filter options
    parser.add_argument('--src-ip', help="Filter by source IP address. Usage: --src-ip 192.168.1.1")
    parser.add_argument('--dst-ip', help="Filter by destination IP address. Usage: --dst-ip 192.168.1.1")
    parser.add_argument('--src-subnet', help="Filter by source subnet. Usage: --src-subnet 192.168.1.0/24")
    parser.add_argument('--dst-subnet', help="Filter by destination subnet. Usage: --dst-subnet 192.168.1.0/24")
    parser.add_argument('--src-port', type=int, help="Filter by source port. Usage: --src-port 80")
    parser.add_argument('--dst-port', type=int, help="Filter by destination port. Usage: --dst-port 80")
    parser.add_argument('--protocol', help="Filter by protocol (e.g., tcp, udp, icmp). Usage: --protocol tcp")
    parser.add_argument('--tcp-flags', help="Filter by TCP flags. Usage: --tcp-flags S")
    parser.add_argument('--mac-oui', help="Filter by OUI of the MAC address. Usage: --mac-oui 00:11:22")
    parser.add_argument('--http-request', help="Filter by HTTP request method. Usage: --http-request GET")
    parser.add_argument('--url', help="Filter by URL matching. Usage: --url example.com")
    parser.add_argument('--date', help="Filter by date. Usage: --date 2024-07-22")
    parser.add_argument('--time', help="Filter by time. Usage: --time 14:30:00")

    return parser.parse_args()

def main():
    setup_logging()
    args = parse_arguments()

    logging.info(f"Script started with arguments: {vars(args)}")

    if args.combine:
        combine_pcaps(args.combine[:-1], args.combine[-1])
    if args.split:
        split_pcap(args.split[0], args.split[1])
    if args.analyze:
        detect_anomalies(args.analyze)
    if args.filter:
        filters = {}
        if args.src_ip:
            filters['src_ip'] = args.src_ip
        if args.dst_ip:
            filters['dst_ip'] = args.dst_ip
        if args.src_subnet:
            filters['src_subnet'] = args.src_subnet
        if args.dst_subnet:
            filters['dst_subnet'] = args.dst_subnet
        if args.src_port:
            filters['src_port'] = args.src_port
        if args.dst_port:
            filters['dst_port'] = args.dst_port
        if args.protocol:
            filters['protocol'] = args.protocol
        if args.tcp_flags:
            filters['tcp_flags'] = args.tcp_flags
        if args.mac_oui:
            filters['mac_oui'] = args.mac_oui
        if args.http_request:
            filters['http_request'] = args.http_request
        if args.url:
            filters['url'] = args.url
        if args.date:
            filters['date'] = args.date
        if args.time:
            filters['time'] = args.time

        filtered_packets = filter_packets(args.filter[0], filters)
        if filtered_packets:
            wrpcap(args.filter[1], filtered_packets)
            print(f"Filtered packets written to {args.filter[1]}")
            logging.info(f"Filtered packets written to {args.filter[1]}")
        else:
            print("No packets matched the filter criteria.")
            logging.info("No packets matched the filter criteria.")

    logging.info("Script finished execution")

if __name__ == "__main__":
    main()
