import socket
import struct
import textwrap

# Unpack ethernet frame
def ethernet_frame_unpack(data):
    dest_mac, src_mac, eth_proto = struct.unpack("!6s 6s H", data[:14])
    return (
        get_mac_addr(dest_mac),  # destination mac address
        get_mac_addr(src_mac),  # source mac address
        socket.htons(eth_proto),  # ethernet protocol
        data[14:],  # payload
    )
# Return formatted MAC address
def get_mac_addr():
