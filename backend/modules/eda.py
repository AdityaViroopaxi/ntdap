# eda.py — NTDAP v4.0 Advanced Exploratory Data Analysis
# Computes 40+ statistical indicators across traffic dimensions.

import pandas as pd
import numpy as np


def analyze(df: pd.DataFrame) -> dict:
    stats = {}

    # ── Basic counts ──────────────────────────────────────────────
    stats["total_packets"] = len(df)
    stats["total_bytes"]   = int(df["packet_length"].sum())

    # ── Packet size stats ─────────────────────────────────────────
    plen = df["packet_length"]
    stats["avg_packet_size"]    = round(float(plen.mean()), 1)
    stats["min_packet_size"]    = int(plen.min())
    stats["max_packet_size"]    = int(plen.max())
    stats["median_packet_size"] = round(float(plen.median()), 1)
    stats["std_packet_size"]    = round(float(plen.std()), 1)
    stats["p95_packet_size"]    = round(float(plen.quantile(0.95)), 1)

    # ── Capture duration ──────────────────────────────────────────
    if "timestamp" in df.columns:
        t_min = df["timestamp"].min()
        t_max = df["timestamp"].max()
        duration = max(t_max - t_min, 0.001)
        stats["capture_duration_seconds"] = round(float(duration), 3)
        stats["packets_per_second"]       = round(len(df) / duration, 2)
        stats["bytes_per_second"]         = round(float(plen.sum()) / duration, 1)
    else:
        stats["capture_duration_seconds"] = 0
        stats["packets_per_second"]       = 0
        stats["bytes_per_second"]         = 0

    # ── Protocol distribution ─────────────────────────────────────
    proto_counts = df["protocol"].value_counts()
    stats["protocol_distribution"]  = proto_counts.to_dict()
    stats["protocol_count"]         = int(proto_counts.nunique())
    stats["most_common_protocol"]   = proto_counts.index[0] if len(proto_counts) > 0 else "Unknown"

    # ── Top IPs ───────────────────────────────────────────────────
    top_src = df["src_ip"].value_counts().head(10)
    top_dst = df["dst_ip"].value_counts().head(10)
    stats["top_source_ips"]      = top_src.to_dict()
    stats["top_destination_ips"] = top_dst.to_dict()
    stats["most_active_src_ip"]  = top_src.index[0] if len(top_src) > 0 else "Unknown"
    stats["unique_src_ips"]      = int(df["src_ip"].nunique())
    stats["unique_dst_ips"]      = int(df["dst_ip"].nunique())

    # ── Top ports ─────────────────────────────────────────────────
    if "dst_port" in df.columns:
        top_ports = df[df["dst_port"] > 0]["dst_port"].value_counts().head(10)
        stats["top_destination_ports"] = {str(int(k)): int(v) for k, v in top_ports.items()}

    if "src_port" in df.columns:
        top_src_ports = df[df["src_port"] > 0]["src_port"].value_counts().head(10)
        stats["top_source_ports"] = {str(int(k)): int(v) for k, v in top_src_ports.items()}

    # ── Top communication pairs ───────────────────────────────────
    if "src_ip" in df.columns and "dst_ip" in df.columns:
        pairs = df.groupby(["src_ip", "dst_ip"]).agg(
            count=("packet_number", "count"),
            total_bytes=("packet_length", "sum"),
        ).nlargest(10, "count").reset_index()
        stats["top_pairs"] = pairs.apply(
            lambda r: {
                "src": r["src_ip"], "dst": r["dst_ip"],
                "count": int(r["count"]), "bytes": int(r["total_bytes"])
            }, axis=1
        ).tolist()

    # ── Private vs public ─────────────────────────────────────────
    if "is_private_src" in df.columns:
        priv = int(df["is_private_src"].sum())
        stats["private_ip_count"] = priv
        stats["public_ip_count"]  = len(df) - priv
        stats["private_pct"]      = round(priv / max(len(df), 1) * 100, 1)

    # ── Inter-arrival time ────────────────────────────────────────
    if "inter_arrival_time" in df.columns:
        iat = df["inter_arrival_time"]
        stats["avg_inter_arrival_ms"]    = round(float(iat.mean()) * 1000, 3)
        stats["median_inter_arrival_ms"] = round(float(iat.median()) * 1000, 3)
        stats["max_inter_arrival_ms"]    = round(float(iat.max()) * 1000, 3)

    # ── TCP flag breakdown ────────────────────────────────────────
    for flag in ["flag_syn", "flag_ack", "flag_rst", "flag_fin", "flag_psh"]:
        if flag in df.columns:
            stats[flag + "_count"] = int(df[flag].sum())

    # ── Payload stats ─────────────────────────────────────────────
    if "payload_length" in df.columns:
        pay = df["payload_length"]
        stats["avg_payload_length"] = round(float(pay.mean()), 1)
        stats["total_payload_bytes"] = int(pay.sum())
        stats["payload_pct"] = round(float(pay.sum()) / max(int(plen.sum()), 1) * 100, 1)

    # ── Flow summary ──────────────────────────────────────────────
    if "flow_packet_count" in df.columns:
        stats["unique_flows"]          = int(df.groupby(["src_ip","dst_ip","src_port","dst_port","protocol"]).ngroups)
        stats["avg_flow_packet_count"] = round(float(df["flow_packet_count"].mean()), 1)
        stats["max_flow_packet_count"] = int(df["flow_packet_count"].max())

    # ── Packet type breakdown ─────────────────────────────────────
    if "packet_type" in df.columns:
        ptype = df["packet_type"].value_counts()
        stats["packet_type_distribution"] = ptype.to_dict()

    # ── Protocol category groups ──────────────────────────────────
    proto_col = df["protocol"].fillna("OTHER").str.upper()
    stats["tcp_based_count"]  = int(proto_col.isin(["TCP","HTTP","HTTPS","SSH","FTP","SMTP","RDP","TELNET","MYSQL","MSSQL","POSTGRES","SMB"]).sum())
    stats["udp_based_count"]  = int(proto_col.isin(["UDP","DNS","DHCP","NTP","SNMP","MDNS","SYSLOG","TFTP"]).sum())
    stats["icmp_count"]       = int(proto_col.isin(["ICMP"]).sum())
    stats["arp_count"]        = int(proto_col.isin(["ARP"]).sum())
    stats["suspicious_count"] = int(proto_col.isin(["METERPRETER","SOCKS"]).sum())

    # ── DNS query stats ───────────────────────────────────────────
    if "dns_query" in df.columns:
        dns_qs = df["dns_query"].dropna()
        if len(dns_qs) > 0:
            stats["dns_query_count"]  = len(dns_qs)
            stats["unique_dns_queries"] = int(dns_qs.nunique())
            stats["top_dns_queries"]  = dns_qs.value_counts().head(5).to_dict()

    # ── HTTP stats ────────────────────────────────────────────────
    if "http_method" in df.columns:
        http_methods = df["http_method"].dropna()
        if len(http_methods) > 0:
            stats["http_request_count"] = len(http_methods)
            stats["http_methods"]       = http_methods.value_counts().to_dict()

    # ── Suspicious activity indicators ────────────────────────────
    if "is_suspicious_port" in df.columns:
        stats["suspicious_port_count"] = int(df["is_suspicious_port"].sum())

    return stats
