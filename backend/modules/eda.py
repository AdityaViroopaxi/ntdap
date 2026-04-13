# eda.py
# EDA = Exploratory Data Analysis
# This file looks at the cleaned data and calculates useful statistics.
# It answers questions like:
#   - How many packets were there?
#   - Which protocol was used most?
#   - Who sent the most traffic?
#   - Added more statistics including top communication pairs, private vs public IP ratio, and port category breakdown.

import pandas as pd
 
def analyze(df):
    """
    Calculate statistics from the packet data.
    Returns a dictionary of stats for the results page.
    """
 
    stats = {}
 
    # --- Basic counts ---
    stats["total_packets"] = len(df)
    stats["total_bytes"]   = int(df["packet_length"].sum())
 
    # --- Packet size info ---
    stats["avg_packet_size"] = round(float(df["packet_length"].mean()), 1)
    stats["min_packet_size"] = int(df["packet_length"].min())
    stats["max_packet_size"] = int(df["packet_length"].max())
 
    # --- Capture duration ---
    if "timestamp" in df.columns:
        duration = df["timestamp"].max() - df["timestamp"].min()
        stats["capture_duration_seconds"] = round(float(duration), 2)
        # Packets per second
        stats["packets_per_second"] = round(
            len(df) / max(duration, 1), 1
        )
    else:
        stats["capture_duration_seconds"] = 0
        stats["packets_per_second"] = 0
 
    # --- Protocol breakdown ---
    protocol_counts = df["protocol"].value_counts()
    stats["protocol_distribution"] = protocol_counts.to_dict()
    stats["most_common_protocol"]  = protocol_counts.index[0] if len(protocol_counts) > 0 else "Unknown"
 
    # --- Top source IPs ---
    top_src = df["src_ip"].value_counts().head(5)
    stats["top_source_ips"]     = top_src.to_dict()
    stats["most_active_src_ip"] = top_src.index[0] if len(top_src) > 0 else "Unknown"
 
    # --- Top destination IPs ---
    top_dst = df["dst_ip"].value_counts().head(5)
    stats["top_destination_ips"] = top_dst.to_dict()
 
    # --- Top destination ports ---
    top_ports = df["dst_port"].value_counts().head(5)
    stats["top_destination_ports"] = {
        str(int(k)): int(v) for k, v in top_ports.items()
    }
 
    # --- Top communication pairs (NEW) ---
    # Which two hosts talked to each other the most?
    if "src_ip" in df.columns and "dst_ip" in df.columns:
        pairs = df.groupby(["src_ip", "dst_ip"]).size().nlargest(5)
        stats["top_pairs"] = [
            {"src": src, "dst": dst, "count": int(count)}
            for (src, dst), count in pairs.items()
        ]
    else:
        stats["top_pairs"] = []
 
    # --- Private vs Public IP ratio (NEW) ---
    if "is_private_src" in df.columns:
        private_count = int(df["is_private_src"].sum())
        stats["private_ip_count"] = private_count
        stats["public_ip_count"]  = len(df) - private_count
 
    # --- Average inter-arrival time (NEW) ---
    if "inter_arrival_time" in df.columns:
        stats["avg_inter_arrival_ms"] = round(
            float(df["inter_arrival_time"].mean()) * 1000, 2
        )
 
    # --- Unique IPs (NEW) ---
    stats["unique_src_ips"] = int(df["src_ip"].nunique())
    stats["unique_dst_ips"] = int(df["dst_ip"].nunique())
 
    return stats