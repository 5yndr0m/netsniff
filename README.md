# NetSniff
> simple low level packet sniffer
> built **==For Education Purpose==**

NetSniff is a low-level network monitoring tool/script built in Python. It captures raw packets directly from the network interface, unpacks their binary headers, and categorizes them based on their respective protocols.

---
## How the NetSniff Works

The NetSniff operates by opening a **Raw Socket**. Unlike standard sockets (*which only give you the "payload" of a message*), raw sockets allow the program to see the entire stack, including the headers added by the operating system and hardware.

- **Socket Type:** `socket.AF_PACKET` (Linux-specific) allows capture at the Layer 2 (Data Link) level.

- **Decoding:** Since data arrives as a stream of bytes, the `struct` module is used to "unpack" these bytes into human-readable variables based on the known bit-lengths of network headers. 
---
## The Data Hierarchy (Layers & Protocols)

NetSniff processes data from the "bottom up," following the encapsulation process.

**Data Flow:** `Ethernet` ➔ `IP` ➔ `TCP/UDP` ➔ `CSV Export`

### Layer 2: The Data Link Layer (Ethernet Frames)

This is the first thing NetSniff sees. Every piece of data on a local network is wrapped in an **Ethernet Frame**.

- **MAC Addresses:** Source and Destination hardware IDs.
- **EtherType:** A field that tells the sniffer what is inside the frame (e.g., `0x0800` and `8` for IPv4 or `0x0806` and `2054` for ARP).

> You can Learn more about numbers from **Internet Assigned Numbers Authority (IANA)**<br/>
> [protocol numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)<br/>
> [IEEE 802 Numbers](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)<br/>

### Layer 3: The Network Layer (IP & ARP)

If the Ethernet Frame contains an IP packet, the NetSniff peels back the Ethernet header to reveal:

- **IPv4:** Handles routing. Key fields include **TTL** (Time to Live) and the **Source/Target IP addresses**.
- **ARP (Address Resolution Protocol):** Used to map an IP address to a physical MAC address.

### Layer 4: The Transport Layer (TCP, UDP, ICMP)

Inside the IP packet lies the "Segment" or "Datagram." This determines how data is delivered:

- **TCP (Transmission Control Protocol):** Connection-oriented. NetSniff tracks **Flags** (SYN, ACK, FIN) which manage the "handshake" between computers.
- **UDP (User Datagram Protocol):** Connectionless and fast. Used for streaming or DNS.
- **ICMP (Internet Control Message Protocol):** Used for error messages and "pings."

---
## Code Architecture

The NetSniff is organized into specialized "unpacker" functions to maintain the "Don't Repeat Yourself" (DRY) principle:

| Function                | Purpose                                                                   |
| ----------------------- | ------------------------------------------------------------------------- |
| `ethernet_frame_unpack` | Extracts MAC addresses and identifies the inner protocol.                 |
| `ipv4_packet_unpack`    | Extracts IP addresses and determines if the payload is TCP, UDP, or ICMP. |
| `tcp_segment`           | Parses ports and sequence numbers; handles bitwise operations for flags.  |
| `udp_datagram_unpack`   | Parses source/destination ports and length.                               |
| `main`                  | The entry point. Handles the infinite capture loop and saves data to CSV. |

---

## Data Storage & Buffer Logic

To prevent the script from slowing down the system (I/O bottleneck), NetSniff uses a **Buffer System**:

1. Packets are stored in the `capture_data_buffer` list.
2. Once the `BUFFER_LIMIT` (50) is reached, the NetSniff writes the entire batch to `capture_data.csv` using **Pandas**.
3. This minimizes the number of times the script has to open and write to the hard drive.
---
### Requirements & Safety

- **Privileges:** This script requires **root/administrative privileges** to open raw sockets.
- **OS:** Designed primarily for **Linux** (due to `AF_PACKET`).
- **Ethical Use:** This tool is for educational and diagnostic purposes. Sniffing traffic on networks you do not own is illegal and unethical.
---
## To Execute
- `python -m venv venv`
- install requirements (Most are already in your venv)
- run using `sudo ./venv/bin/python netsniff.py`
- `Ctrl + C` to stop
- in the same directory a `capture_data.csv` will be created.
---
## Lessons Learned

- **Binary Data Handling:** Navigating the `struct` module to unpack network-byte-order (Big Endian) data into Python-native types.
- **Privilege Management:** Handling the requirement for `sudo` while maintaining a Python virtual environment (`venv`).
- **Data Integrity:** Implementing a "Schema-First" dictionary approach to ensure CSV consistency across varying protocols (ARP vs IPv4).
