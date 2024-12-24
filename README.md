# Packet Sniffer
*A basic CLI packet sniffer implemented in C using the libpcap library.*

This packet sniffer captures network packets and provides basic information about each one. It includes details from the Ethernet header, such as source and destination MAC addresses, IP header information, and TCP-specific details. The program also supports filtering packets by port number.

## Features
- Capture network packets in real time.
- Display detailed information about each packet, including:
  - Ethernet header
  - Source and destination MAC addresses
  - IP header information (source and destination IP addresses)
  - TCP header details (source and destination ports, sequence number, etc.)
- Ability to filter packets based on a specific port.

## Command-Line Arguments

The program supports the following command-line options:

- `-d <device>`: Specify the network device to capture packets from.
- `-p <port>`: Filter packets by the specified port number.
- `-h`: Display the help message with available options.

If no arguments are provided, the program will automatically find the default network device and capture all packets without any filtering.

## Build
Ensure the libpcap library is installed and run make
```bash
make
sudo ./sniffer
```

## Example Usage

```bash
# To run the sniffer with a specific device and port filter
sudo ./sniffer -d eth0 -p 80

# To capture packets on the default device
sudo ./sniffer

# To display help
./sniffer -h
```

