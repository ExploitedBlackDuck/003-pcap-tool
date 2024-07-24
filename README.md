# pcap_tool

## Overview

`pcap_tool` is a versatile Python script designed for managing and analyzing pcap (packet capture) files. It provides functionality to combine multiple pcap files, split a pcap file into individual packets, detect anomalies within pcap files, and filter packets based on various criteria. The tool is compatible with Windows, macOS, and Linux.

## Features

- **Combine pcap files**: Merge multiple pcap files into a single pcap file.
- **Split pcap file**: Split a single pcap file into multiple files, each containing one packet.
- **Analyze pcap file**: Detect anomalies in a pcap file.
- **Filter pcap file**: Filter packets based on a variety of criteria, such as IP addresses, subnets, ports, protocols, TCP flags, MAC OUI, HTTP requests, URLs, dates, and times.

## Installation

Ensure you have Python installed on your system along with the required libraries. You can install the necessary libraries using pip:

```bash
pip install scapy ipaddress
```

## Script Usage

### Command-Line Options

The `pcap_tool` script supports the following command-line options:

- `--combine`: Combine multiple pcap files into one.
- `--split`: Split a pcap file into multiple files.
- `--analyze`: Analyze a pcap file for anomalies.
- `--filter`: Filter packets based on criteria.

### Filter Options

The following filter options can be used with the `--filter` command:

- `--src-ip`: Filter by source IP address.
- `--dst-ip`: Filter by destination IP address.
- `--src-subnet`: Filter by source subnet.
- `--dst-subnet`: Filter by destination subnet.
- `--src-port`: Filter by source port.
- `--dst-port`: Filter by destination port.
- `--protocol`: Filter by protocol (e.g., tcp, udp, icmp).
- `--tcp-flags`: Filter by TCP flags.
- `--mac-oui`: Filter by OUI of the MAC address.
- `--http-request`: Filter by HTTP request method.
- `--url`: Filter by URL matching.
- `--date`: Filter by date.
- `--time`: Filter by time.

### Help Option

You can display the help message with detailed descriptions and usage examples for each option using:

```bash
python pcap_tool.py --help
```

### Example Usage

#### Combine Multiple Pcap Files

Combine multiple pcap files into a single pcap file:

```bash
python pcap_tool.py --combine file1.pcap file2.pcap output.pcap
```

#### Split a Pcap File

Split a pcap file into multiple files:

```bash
python pcap_tool.py --split input.pcap output_prefix
```

#### Analyze a Pcap File for Anomalies

Analyze a pcap file to detect anomalies:

```bash
python pcap_tool.py --analyze input.pcap
```

#### Filter Packets in a Pcap File

Filter packets based on source IP address and write the filtered packets to a new file:

```bash
python pcap_tool.py --filter input.pcap output.pcap --src-ip 192.168.1.1
```

Filter packets based on a combination of criteria:

```bash
python pcap_tool.py --filter input.pcap output.pcap --src-ip 192.168.1.1 --dst-port 80 --protocol tcp
```
