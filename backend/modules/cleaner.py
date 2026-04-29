# cleaner.py — NTDAP v3.0 Advanced Data Cleaner
# - Smarter deduplication (timestamp + src + dst + len, not all cols)
# - Fills missing IPs with "Unknown" instead of dropping
# - Validates and clips extreme values (outlier TTL, window_size, etc.)
# - Normalises protocol names to uppercase
# - Computes additional derived columns used by ML

import pandas as pd
import numpy as np


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean and normalise raw packet DataFrame.
    Returns enriched, cleaned DataFrame.
    """
    original = len(df)

    # ── 1. Smarter duplicate detection ────────────────────────────
    subset = [c for c in ["timestamp", "src_ip", "dst_ip", "packet_length"] if c in df.columns]
    df = df.drop_duplicates(subset=subset)

    # ── 2. Remove zero-length packets ─────────────────────────────
    df = df[df["packet_length"] > 0]

    # ── 3. Fill missing IPs ────────────────────────────────────────
    df["src_ip"] = df["src_ip"].fillna("Unknown")
    df["dst_ip"] = df["dst_ip"].fillna("Unknown")

    # ── 4. Normalise protocol to uppercase string ──────────────────
    df["protocol"] = df["protocol"].fillna("OTHER").str.upper().str.strip()

    # ── 5. Fill numeric columns ────────────────────────────────────
    num_cols = [
        "src_port", "dst_port", "ttl", "window_size",
        "payload_length", "icmp_type", "icmp_code", "header_length",
        "is_private_src", "is_private_dst", "is_arp", "is_multicast",
        "is_suspicious_port", "inter_arrival_time", "payload_ratio",
        "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
        "tcp_flags_value", "flow_packet_count", "flow_bytes_total",
        "flow_duration", "iat_rolling_std",
    ]
    for col in num_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # ── 6. Clip extreme / nonsensical values ───────────────────────
    if "ttl" in df.columns:
        df["ttl"] = df["ttl"].clip(0, 255)
    if "window_size" in df.columns:
        df["window_size"] = df["window_size"].clip(0, 65535)
    if "packet_length" in df.columns:
        df["packet_length"] = df["packet_length"].clip(1, 65535)
    if "inter_arrival_time" in df.columns:
        df["inter_arrival_time"] = df["inter_arrival_time"].clip(0, 60)

    # ── 7. Ensure integer types for byte fields ────────────────────
    for col in [
        "packet_length",
        "payload_length",
        "src_port",
        "dst_port",
        "ttl",
        "window_size",
        "icmp_type",
        "icmp_code"
    ]:
        if col in df.columns:
            df[col] = (
                pd.to_numeric(df[col], errors="coerce")
                .replace([np.inf, -np.inf], 0)
                .fillna(0)
                .astype(int)
            )

    # ── 8. Compute log-transformed features for ML ─────────────────
    df["log_packet_length"]      = np.log1p(df["packet_length"])
    df["log_inter_arrival_time"] = np.log1p(df.get("inter_arrival_time", 0))
    df["log_flow_bytes"]         = np.log1p(df.get("flow_bytes_total", 0))

    # ── 9. Boolean combination features ───────────────────────────
    # SYN flood indicator: SYN=1, ACK=0 (connection not established)
    if "flag_syn" in df.columns and "flag_ack" in df.columns:
        df["syn_no_ack"] = ((df["flag_syn"] == 1) & (df["flag_ack"] == 0)).astype(int)

    # ── 10. Reset index ────────────────────────────────────────────
    df = df.reset_index(drop=True)

    removed = original - len(df)
    print(f"[Cleaner] Removed {removed} rows → {len(df)} packets remain | {len(df.columns)} features")
    return df
