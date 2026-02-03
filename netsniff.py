import socket
import struct
import textwrap
from ast import While


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


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

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
