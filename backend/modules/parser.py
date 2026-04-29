# parser.py — NTDAP v3.0 Advanced Packet Parser
# Extracts 35+ features per packet for high-accuracy ML detection.
# Supports: TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP, HTTPS, SSH, FTP,
#           SMTP, RDP, Telnet, NTP, SNMP, SMB, MYSQL, REDIS and more.

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
from scapy.layers.l2 import Ether
import pandas as pd
import ipaddress

# ── Port → Protocol map (extended to 40+ protocols) ──────────────
PORT_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP",  53: "DNS",  67: "DHCP", 68: "DHCP",
    69: "TFTP",  80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP",  137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    179: "BGP",  389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "ISAKMP", 514: "SYSLOG", 515: "LPD",
    587: "SMTP-SUBMISSION", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OPENVPN", 1433: "MSSQL",
    1521: "ORACLE-DB", 1723: "PPTP",
    3306: "MYSQL", 3389: "RDP",
    4444: "METERPRETER", 5060: "SIP",
    5222: "XMPP", 5432: "POSTGRES", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    8888: "HTTP-DEV", 9200: "ELASTICSEARCH",
    27017: "MONGODB", 5353: "MDNS",
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 12345, 6667, 6666, 1234, 9999, 54321, 65535}


def parse_pcap(file_path):
    """
    Read a PCAP/PCAPNG file. Returns a DataFrame with 35+ features per packet.
    """
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        raise ValueError(f"Cannot read PCAP file: {e}")

    rows = []
    first_ts = None
    prev_ts  = None

    for i, pkt in enumerate(packets):
        ts = float(pkt.time)
        if first_ts is None:
            first_ts = ts
        relative_time = round(ts - first_ts, 6)
        inter_arrival = max(round(ts - prev_ts, 6), 0.0) if prev_ts is not None else 0.0
        prev_ts = ts

        row = _make_row(i, ts, relative_time, inter_arrival, pkt)
        rows.append(row)

    df = pd.DataFrame(rows)

    # ── Inter-arrival recalculate from diff (cleaner) ─────────────
    df["inter_arrival_time"] = df["timestamp"].diff().fillna(0).clip(lower=0)

    # ── Payload ratio ─────────────────────────────────────────────
    df["payload_ratio"] = (
        df["payload_length"] / df["packet_length"].replace(0, 1)
    ).round(4)

    # ── Flow-level statistics ─────────────────────────────────────
    df = _add_flow_features(df)

    # ── Burstiness proxy ──────────────────────────────────────────
    df["iat_rolling_std"] = (
        df["inter_arrival_time"]
        .rolling(window=5, min_periods=1)
        .std()
        .fillna(0.0)
        .round(6)
    )

    print(f"[Parser] {len(df)} packets | {len(df.columns)} features")
    return df


# ─────────────────────────────────────────────────────────────────

def _make_row(i, ts, rel_time, iat, pkt):
    row = {
        "packet_number":      i + 1,
        "timestamp":          ts,
        "relative_time":      rel_time,
        "inter_arrival_time": iat,
        "packet_length":      len(pkt),
        "payload_length":     0,
        "protocol":           "OTHER",
        "src_ip": "Unknown",
        "dst_ip": "Unknown",
        "src_port": 0,
        "dst_port": 0,
        "ttl": 0,
        "window_size": 0,
        "icmp_type": 0,
        "icmp_code": 0,
        "header_length":      0,
        "is_private_src":     0,
        "is_private_dst":     0,
        "is_arp":             0,
        "is_multicast":       0,
        "is_suspicious_port": 0,
        # TCP flags individual bits
        "flag_syn": 0, "flag_ack": 0, "flag_fin": 0,
        "flag_rst": 0, "flag_psh": 0, "flag_urg": 0,
        # App-layer extras
        "dns_query":    None,
        "http_method":  None,
        "http_host":    None,
        # Frame
        "src_mac":  None,
        "dst_mac":  None,
        "packet_type": "DATA",
    }

    # Ethernet
    if Ether in pkt:
        row["src_mac"] = pkt[Ether].src
        row["dst_mac"] = pkt[Ether].dst

    # ARP
    if ARP in pkt:
        row["protocol"] = "ARP"
        row["src_ip"]   = pkt[ARP].psrc
        row["dst_ip"]   = pkt[ARP].pdst
        row["is_arp"]   = 1
        row["packet_type"] = "DISCOVERY"

    # IP
    if IP in pkt:
        ip = pkt[IP]
        row["src_ip"]         = ip.src
        row["dst_ip"]         = ip.dst
        row["ttl"]            = ip.ttl
        row["header_length"]  = ip.ihl * 4
        row["is_private_src"] = 1 if _is_private(ip.src) else 0
        row["is_private_dst"] = 1 if _is_private(ip.dst) else 0

    # Multicast
    dst = row.get("dst_ip") or ""
    try:
        row["is_multicast"] = 1 if ipaddress.ip_address(dst).is_multicast else 0
    except Exception:
        pass

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        sp, dp = tcp.sport, tcp.dport
        proto = PORT_MAP.get(dp) or PORT_MAP.get(sp) or "TCP"
        row["protocol"]        = proto
        row["src_port"]        = sp
        row["dst_port"]        = dp
        row["tcp_flags"]       = str(tcp.flags)
        row["tcp_flags_value"] = int(tcp.flags)
        row["window_size"]     = tcp.window
        flags = int(tcp.flags)
        row["flag_syn"] = 1 if flags & 0x02 else 0
        row["flag_ack"] = 1 if flags & 0x10 else 0
        row["flag_fin"] = 1 if flags & 0x01 else 0
        row["flag_rst"] = 1 if flags & 0x04 else 0
        row["flag_psh"] = 1 if flags & 0x08 else 0
        row["flag_urg"] = 1 if flags & 0x20 else 0
        try:
            row["payload_length"] = len(bytes(tcp.payload))
        except Exception:
            pass

        # Packet type classification
        if row["flag_syn"] and not row["flag_ack"]:
            row["packet_type"] = "HANDSHAKE"
        elif row["flag_rst"]:
            row["packet_type"] = "RESET"
        elif row["flag_fin"]:
            row["packet_type"] = "TEARDOWN"

        # HTTP sniff
        try:
            raw = bytes(tcp.payload)[:256].decode(errors="ignore")
            for method in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "):
                if raw.startswith(method):
                    row["http_method"] = method.strip()
                    for line in raw.split("\r\n"):
                        if line.lower().startswith("host:"):
                            row["http_host"] = line[5:].strip()[:80]
                            break
                    break
        except Exception:
            pass

    # UDP
    elif UDP in pkt:
        udp = pkt[UDP]
        sp, dp = udp.sport, udp.dport
        proto = PORT_MAP.get(dp) or PORT_MAP.get(sp) or "UDP"
        row["protocol"] = proto
        row["src_port"] = sp
        row["dst_port"] = dp
        try:
            row["payload_length"] = len(bytes(udp.payload))
        except Exception:
            pass
        if proto in ("DNS", "MDNS", "NETBIOS", "DHCP"):
            row["packet_type"] = "DISCOVERY"

    # ICMP
    elif ICMP in pkt:
        row["protocol"]   = "ICMP"
        row["icmp_type"]  = pkt[ICMP].type
        row["icmp_code"]  = pkt[ICMP].code
        row["packet_type"] = "CONTROL"

    # DNS query
    if DNS in pkt:
        try:
            dns = pkt[DNS]
            if dns.qd:
                row["dns_query"] = dns.qd.qname.decode(errors="replace").rstrip(".")
        except Exception:
            pass

    # Suspicious port flag
    sp = row.get("src_port")
    dp2 = row.get("dst_port")
    if sp in SUSPICIOUS_PORTS or dp2 in SUSPICIOUS_PORTS:
        row["is_suspicious_port"] = 1

    return row


def _add_flow_features(df):
    """Compute per-flow packet count, bytes, duration."""
    if df.empty:
        df["flow_packet_count"] = 0
        df["flow_bytes_total"]  = 0
        df["flow_duration"]     = 0.0
        return df

    def fk(r):
        return (
            str(r.get("src_ip") or ""),
            str(r.get("dst_ip") or ""),
            int(r.get("src_port") or 0),
            int(r.get("dst_port") or 0),
            str(r.get("protocol") or ""),
        )

    df["_fk"] = df.apply(fk, axis=1)
    df["flow_packet_count"] = df.groupby("_fk")["packet_length"].transform("count")
    df["flow_bytes_total"]  = df.groupby("_fk")["packet_length"].transform("sum")
    df["flow_duration"]     = df.groupby("_fk")["timestamp"].transform(
        lambda x: round(x.max() - x.min(), 4)
    )
    df.drop(columns=["_fk"], inplace=True)
    return df


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False
