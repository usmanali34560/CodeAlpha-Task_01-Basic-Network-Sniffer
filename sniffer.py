import socket
import struct
import textwrap

# Function to format multi-line data (for readability)
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Function to unpack Ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Convert a MAC address to a human-readable format
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Main function to capture network packets
def sniff_packets():
    # Create a raw socket (AF_PACKET allows capturing Ethernet packets)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # Capture data
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        # Check if it's an IP packet
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'IPv4 Packet: Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Source IP: {src}, Destination IP: {target}')

            # If it's ICMP protocol
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'Data:\n{format_multi_line("    ", data)}')

            # If it's TCP protocol
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(f'TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'Flags:')
                print(f'   URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}')
                print(f'   RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f'Data:\n{format_multi_line("    ", data)}')

            # If it's UDP protocol
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f'UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

                print(f'Data:\n{format_multi_line("    ", data)}')

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format an IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

if __name__ == '__main__':
    sniff_packets()
