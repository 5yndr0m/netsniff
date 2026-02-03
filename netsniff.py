import os
import socket
import struct
import textwrap
import time

import pandas as pd

# Helper tabs
TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

capture_data_buffer = []
BUFFER_LIMIT = 50

base_fields = {
    "timestamp": time.time(),
    "dest_mac": None,
    "src_mac": None,
    "eth_proto": None,
    "ip_version": None,
    "ip_header_length": None,
    "ip_ttl": None,
    "ip_protocol": None,
    "ip_src_addr": None,
    "ip_target_addr": None,
    "icmp_type": None,
    "icmp_code": None,
    "icmp_checksum": None,
    "tcp_src_port": None,
    "tcp_dest_port": None,
    "tcp_sequence": None,
    "tcp_acknowledgment": None,
    "tcp_offset": None,
    "tcp_flag_urg": None,
    "tcp_flag_ack": None,
    "tcp_flag_psh": None,
    "tcp_flag_rst": None,
    "tcp_flag_syn": None,
    "tcp_flag_fin": None,
    "udp_src_port": None,
    "udp_dest_port": None,
    "udp_length": None,
    "other_proto": None,
    "other_data": None,
}


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


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    print("Starting Sniffer...")
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        print("Sniffer Started...")

        # Infinite loop to keep sniffing packets
        while True:
            packet_data = base_fields.copy()
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame_unpack(raw_data)

            packet_data.update(
                {
                    "timestamp": time.time(),
                    "dest_mac": dest_mac,
                    "src_mac": src_mac,
                    "eth_proto": eth_proto,
                }
            )

            # print("\nEthernet Frame:")
            # print(
            #     TAB_1
            #     + "Destination: {}, Source: {}, Protocol: {}".format(
            #         dest_mac, src_mac, eth_proto
            #     )
            # )

            # IPv4 == 8
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = (
                    ipv4_packet_unpack(data)
                )

                packet_data.update(
                    {
                        "ip_version": version,
                        "ip_header_length": header_length,
                        "ip_ttl": ttl,
                        "ip_protocol": proto,
                        "ip_src_addr": src,
                        "ip_target_addr": target,
                    }
                )
                # packet_data["ip_version"] = version
                # packet_data["ip_header_length"] = header_length
                # packet_data["ip_ttl"] = ttl
                # packet_data["ip_protocol"] = proto
                # packet_data["ip_src_addr"] = src
                # packet_data["ip_target_addr"] = target

                # print(TAB_1 + "IPv4 Packet:")
                # print(
                #     TAB_2
                #     + "Version: {}, Header Length: {}, TTL: {}".format(
                #         version, header_length, ttl
                #     )
                # )
                # print(
                #     TAB_2
                #     + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target)
                # )

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet_unpack(data)

                    packet_data.update(
                        {
                            "icmp_type": icmp_type,
                            "icmp_code": code,
                            "icmp_checksum": checksum,
                        }
                    )
                    # packet_data["icmp_type"] = icmp_type
                    # packet_data["icmp_code"] = code
                    # packet_data["icmp_checksum"] = checksum

                    # print(TAB_1 + "ICMP Packet:")
                    # print(
                    #     TAB_2
                    #     + "Type: {}, Code: {}, Checksum: {}".format(
                    #         icmp_type, code, checksum
                    #     )
                    # )
                    # print(TAB_2 + "Data: ")
                    # print(format_multi_line(DATA_TAB_3, data))

                # TCP
                elif proto == 6:
                    (
                        src_port,
                        dest_port,
                        sequence,
                        acknowledgment,
                        offset,
                        flag_urg,
                        flag_ack,
                        flag_psh,
                        flag_rst,
                        flag_syn,
                        flag_fin,
                        data,
                    ) = tcp_segment(data)

                    packet_data.update(
                        {
                            "tcp_src_port": src_port,
                            "tcp_dest_port": dest_port,
                            "tcp_sequence": sequence,
                            "tcp_acknowledgment": acknowledgment,
                            "tcp_offset": offset,
                            "tcp_flag_urg": flag_urg,
                            "tcp_flag_ack": flag_ack,
                            "tcp_flag_psh": flag_psh,
                            "tcp_flag_rst": flag_rst,
                            "tcp_flag_syn": flag_syn,
                            "tcp_flag_fin": flag_fin,
                        }
                    )

                    # packet_data["tcp_src_port"] = src_port
                    # packet_data["tcp_dest_port"] = dest_port
                    # packet_data["tcp_sequence"] = sequence
                    # packet_data["tcp_acknowledgment"] = acknowledgment
                    # packet_data["tcp_offset"] = offset
                    # packet_data["tcp_flag_urg"] = flag_urg
                    # packet_data["tcp_flag_ack"] = flag_ack
                    # packet_data["tcp_flag_psh"] = flag_psh
                    # packet_data["tcp_flag_rst"] = flag_rst
                    # packet_data["tcp_flag_syn"] = flag_syn
                    # packet_data["tcp_flag_fin"] = flag_fin

                    # print(TAB_1 + "TCP Segment:")
                    # print(
                    #     TAB_2
                    #     + "Source Port: {}, Destination Port: {}".format(
                    #         src_port, dest_port
                    #     )
                    # )
                    # print(
                    #     TAB_2
                    #     + "Sequence: {}, Acknowledgment: {}, Offset: {}".format(
                    #         sequence, acknowledgment, offset
                    #     )
                    # )
                    # print(TAB_2 + "Flags: ")
                    # print(
                    #     TAB_2
                    #     + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(
                    #         flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
                    #     )
                    # )
                    # print(TAB_2 + "Data: ")
                    # print(format_multi_line(DATA_TAB_3, data))

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = udp_datagram_unpack(data)

                    packet_data.update(
                        {
                            "udp_src_port": src_port,
                            "udp_dest_port": dest_port,
                            "udp_length": length,
                        }
                    )

                    # packet_data["udp_src_port"] = src_port
                    # packet_data["udp_dest_port"] = dest_port
                    # packet_data["udp_length"] = length

                    # print(TAB_1 + "UDP Segment:")
                    # print(
                    #     TAB_2
                    #     + "Source Port: {}, Destination Port: {}, Length: {}".format(
                    #         src_port, dest_port, length
                    #     )
                    # )

                # Other
                else:
                    packet_data["other_proto"] = proto
                    packet_data["other_data"] = data.hex()
                    # print(TAB_1 + "Data: ")
                    # print(format_multi_line(DATA_TAB_3, data))

            capture_data_buffer.append(packet_data)

            if len(capture_data_buffer) >= BUFFER_LIMIT:
                df = pd.DataFrame(capture_data_buffer)
                df.to_csv(
                    "capture_data.csv",
                    mode="a",
                    index=False,
                    header=True if not os.path.exists("capture_data.csv") else False,
                )
                capture_data_buffer.clear()

    except KeyboardInterrupt:
        if capture_data_buffer:
            pd.DataFrame(capture_data_buffer).to_csv(
                "capture_data.csv", mode="a", index=False, header=False
            )
            print("\nSniffer Stopped. Remaining data saved.")
        conn.close()


main()
