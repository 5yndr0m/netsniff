import socket
import struct
import textwrap


# Return formatted MAC address (output -> XX:XX:XX:XX:XX:XX)
def get_mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


# Unpack ethernet frame
def ethernet_frame_unpack(data):
    dest_mac, src_mac, eth_proto = struct.unpack("!6s 6s H", data[:14])
    return (
        get_mac_addr(dest_mac),  # destination mac address
        get_mac_addr(src_mac),  # source mac address
        socket.htons(eth_proto),  # ethernet protocol
        data[14:],  # payload
    )


# Unpack IPv4 packet
def ipv4_packet_unpack(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4_format(src),
        ipv4_format(target),
        data[header_length:],
    )


# Format IPv4 address
def ipv4_format(addr):
    return ".".join(map(str, addr))


# Unpack ICMP packet
def icmp_packet_unpack(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = (
        struct.unpack("! H H L L H", data[:14])
    )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgement,
        offset,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:],
    )


# Unpack UDP datagram
def udp_datagram_unpack(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Infinite loop to keep sniffing packets
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame_unpack(raw_data)
        print("\nEthernet Frame:")
        print(
            "Destination: {}, Source: {}, Protocol: {}".format(
                dest_mac, src_mac, eth_proto
            )
        )


main()
