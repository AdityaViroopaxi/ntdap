# cleaner.py
# IMPROVED:
# - No longer drops packets with missing IPs (was causing packet count loss)
# - Instead fills missing IPs with "Unknown" and keeps the packet
# - Smarter duplicate detection (by timestamp + size, not all columns)

import pandas as pd


def clean_data(df):
    """
    Take the raw packet DataFrame and clean it up.
    Returns a cleaner version of the data.
    """

    original_count = len(df)

    # Step 1: Smarter duplicate removal
    # Only drop packets with the EXACT same timestamp AND size
    # (Previously used drop_duplicates() on all columns which was too aggressive)
    df = df.drop_duplicates(subset=["timestamp", "packet_length"])

    # Step 2: Keep packets with missing IPs but label them "Unknown"
    # (Previously dropped them — this was causing the 49 → 27 packet loss)
    df["src_ip"] = df["src_ip"].fillna("Unknown")
    df["dst_ip"] = df["dst_ip"].fillna("Unknown")

    # Step 3: Remove packets with zero length (truly broken packets)
    df = df[df["packet_length"] > 0]

    # Step 4: Fill in missing numbers with 0
    number_columns = [
        "src_port", "dst_port", "ttl", "window_size",
        "payload_length", "icmp_type", "header_length",
        "is_private_src", "is_private_dst", "is_arp",
        "inter_arrival_time", "payload_ratio"
    ]
    for col in number_columns:
        if col in df.columns:
            df[col] = df[col].fillna(0)

    # Step 5: Make sure these are whole numbers
    df["packet_length"]  = df["packet_length"].astype(int)
    df["payload_length"] = df["payload_length"].astype(int)

    # Step 6: Fill missing protocol with "OTHER"
    df["protocol"] = df["protocol"].fillna("OTHER")

    # Step 7: Reset row numbers
    df = df.reset_index(drop=True)

    removed = original_count - len(df)
    print(f"Cleaning done. Removed {removed} packets. {len(df)} packets remaining.")

    return df