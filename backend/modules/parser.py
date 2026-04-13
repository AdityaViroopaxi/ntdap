# parser.py
# This file reads a PCAP file and pulls out useful information from each packet.
# IMPROVED: Now extracts more features for better ML detection.

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
import pandas as pd


def parse_pcap(file_path):
    """
    Read a PCAP file and return a table (DataFrame) of packet info.
    Each row = one packet. Each column = one feature of that packet.
    """

    # Step 1: Read all packets from the file
    packets = rdpcap(file_path)

    # Step 2: Go through each packet and extract information
    rows = []
    first_timestamp = None  # We use this to calculate relative time

    for i, packet in enumerate(packets):

        # Start with empty values for this packet
        row = {
            "packet_number":    i + 1,
            "timestamp":        float(packet.time),
            "relative_time":    0.0,        # NEW: time since first packet
            "packet_length":    len(packet),
            "protocol":         "OTHER",
            "src_ip":           None,
            "dst_ip":           None,
            "src_port":         None,
            "dst_port":         None,
            "ttl":              None,
            "tcp_flags":        None,
            "window_size":      None,
            "payload_length":   0,
            "icmp_type":        None,
            "is_private_src":   0,          # NEW: is source IP internal?
            "is_private_dst":   0,          # NEW: is destination IP internal?
            "is_arp":           0,          # NEW: is it an ARP packet?
            "header_length":    0,          # NEW: size of the IP header
        }

        # Save the first timestamp so we can calculate relative times
        if first_timestamp is None:
            first_timestamp = float(packet.time)

        # Relative time = how many seconds after the first packet
        row["relative_time"] = round(float(packet.time) - first_timestamp, 4)

        # ── ARP packets (no IP layer) ──────────────────
        if ARP in packet:
            row["protocol"]  = "ARP"
            row["src_ip"]    = packet[ARP].psrc   # ARP has its own src/dst IP
            row["dst_ip"]    = packet[ARP].pdst
            row["is_arp"]    = 1

        # ── IP layer ───────────────────────────────────
        if IP in packet:
            row["src_ip"]        = packet[IP].src
            row["dst_ip"]        = packet[IP].dst
            row["ttl"]           = packet[IP].ttl
            row["header_length"] = packet[IP].ihl * 4  # ihl is in 32-bit words

            # Check if the IP is a private (internal) address
            row["is_private_src"] = 1 if _is_private(packet[IP].src) else 0
            row["is_private_dst"] = 1 if _is_private(packet[IP].dst) else 0

        # ── TCP ────────────────────────────────────────
        if TCP in packet:
            row["protocol"]    = "TCP"
            row["src_port"]    = packet[TCP].sport
            row["dst_port"]    = packet[TCP].dport
            row["tcp_flags"]   = str(packet[TCP].flags)
            row["window_size"] = packet[TCP].window

            # Identify protocol by port number
            if   packet[TCP].dport == 80  or packet[TCP].sport == 80:
                row["protocol"] = "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                row["protocol"] = "HTTPS"
            elif packet[TCP].dport == 22  or packet[TCP].sport == 22:
                row["protocol"] = "SSH"
            elif packet[TCP].dport == 21  or packet[TCP].sport == 21:
                row["protocol"] = "FTP"
            elif packet[TCP].dport == 23  or packet[TCP].sport == 23:
                row["protocol"] = "TELNET"

        # ── UDP ────────────────────────────────────────
        elif UDP in packet:
            row["protocol"] = "UDP"
            row["src_port"] = packet[UDP].sport
            row["dst_port"] = packet[UDP].dport

            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                row["protocol"] = "DNS"
            elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                row["protocol"] = "DHCP"

        # ── ICMP ───────────────────────────────────────
        elif ICMP in packet:
            row["protocol"]  = "ICMP"
            row["icmp_type"] = packet[ICMP].type

        # ── Payload length ─────────────────────────────
        try:
            row["payload_length"] = len(packet.payload)
        except:
            row["payload_length"] = 0

        rows.append(row)

    # Step 3: Turn into a DataFrame
    df = pd.DataFrame(rows)

    # Step 4: Calculate inter-arrival time (NEW)
    # This is the time gap between each packet and the previous one
    # Useful for detecting floods (very low inter-arrival time)
    df["inter_arrival_time"] = df["timestamp"].diff().fillna(0)
    df["inter_arrival_time"] = df["inter_arrival_time"].clip(lower=0)

    # Step 5: Calculate payload ratio (NEW)
    # What fraction of the packet is actual data (vs headers)?
    df["payload_ratio"] = df.apply(
        lambda r: round(r["payload_length"] / r["packet_length"], 3)
        if r["packet_length"] > 0 else 0,
        axis=1
    )

    print(f"Parsed {len(df)} packets with {len(df.columns)} features each.")
    return df


def _is_private(ip):
    """
    Check if an IP address is private (internal network).
    Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
    """
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except:
        return False