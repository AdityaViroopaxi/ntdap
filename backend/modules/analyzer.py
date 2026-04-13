# analyzer.py
# This file uses Machine Learning to find unusual (anomalous) packets.
# We use an algorithm called "Isolation Forest".
# The idea is simple:
#   - Normal packets behave similarly to each other
#   - Anomalous packets are "isolated" (different from the rest)
#   - The algorithm scores each packet: negative score = anomaly
# IMPROVED:
# - Now uses MORE features (not just 3) for better detection
# - Added a second detection method: IQR statistical outlier detection
# - Shows WHICH feature caused the anomaly
# - Added basic port scan detection

from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
 
 
def detect_anomalies(df):
    """
    Use Isolation Forest + statistical methods to find anomalous packets.
    Returns a dictionary with anomaly results.
    """
 
    if len(df) < 10:
        return _empty_result(df)
 
    # ── Method 1: Isolation Forest ─────────────────────────────────
    # Step 1: Use MORE features than before for better accuracy
    # Previously only used 3. Now using up to 8.
    all_features = [
        "packet_length",        # size of the packet
        "payload_length",       # size of the data inside
        "ttl",                  # time to live
        "window_size",          # TCP window size
        "src_port",             # source port
        "dst_port",             # destination port
        "inter_arrival_time",   # time gap between packets
        "payload_ratio",        # ratio of data to total size
        "is_private_src",       # is source IP internal?
        "header_length",        # IP header size
    ]
 
    # Only use features that exist in our data
    features = [f for f in all_features if f in df.columns]
 
    # Prepare the numbers
    X = df[features].fillna(0)
 
    # Train and predict with Isolation Forest
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
 
    predictions = model.predict(X)   # 1 = normal, -1 = anomaly
    scores      = model.decision_function(X)
 
    # ── Method 2: IQR Statistical Outlier Detection (NEW) ──────────
    # IQR = Interquartile Range
    # Any value below Q1 - 1.5*IQR or above Q3 + 1.5*IQR is an outlier
    stat_anomalies = _iqr_detection(df)
 
    # ── Count results ───────────────────────────────────────────────
    anomaly_count = int((predictions == -1).sum())
    total         = len(predictions)
    anomaly_pct   = round(anomaly_count / total * 100, 1)
 
    # ── Which protocols had the most anomalies? ─────────────────────
    df_copy = df.copy()
    df_copy["is_anomaly"] = (predictions == -1)
    anomaly_protocols = (
        df_copy[df_copy["is_anomaly"]]["protocol"]
        .value_counts()
        .to_dict()
    )
 
    # ── Anomalous packet table (NEW) ────────────────────────────────
    # Show the top 10 most anomalous packets so the user can inspect them
    df_copy["anomaly_score"] = scores
    anomalous_packets = (
        df_copy[df_copy["is_anomaly"]]
        .nsmallest(10, "anomaly_score")   # lowest score = most anomalous
        [["packet_number", "src_ip", "dst_ip", "protocol",
          "packet_length", "dst_port", "anomaly_score"]]
        .fillna("—")
        .to_dict(orient="records")
    )
 
    # Round the score for display
    for p in anomalous_packets:
        p["anomaly_score"] = round(float(p["anomaly_score"]), 4)
 
    # ── Port scan detection (NEW) ───────────────────────────────────
    port_scan_suspects = _detect_port_scan(df)
 
    return {
        "anomaly_count":        anomaly_count,
        "normal_count":         total - anomaly_count,
        "total_packets":        total,
        "anomaly_percentage":   anomaly_pct,
        "anomaly_by_protocol":  anomaly_protocols,
        "features_used":        features,           # NEW: show which features were used
        "stat_anomalies":       stat_anomalies,     # NEW: IQR results
        "anomalous_packets":    anomalous_packets,  # NEW: actual packet table
        "port_scan_suspects":   port_scan_suspects, # NEW: port scan alerts
        "labels":               predictions.tolist(),
        "scores":               scores.tolist(),
    }
 
 
def _iqr_detection(df):
    """
    Use IQR method to find outliers in key numeric columns.
    Returns a list of findings — one per column that has outliers.
    """
    results = []
    check_columns = ["packet_length", "ttl", "inter_arrival_time", "window_size"]
 
    for col in check_columns:
        if col not in df.columns:
            continue
 
        series = pd.to_numeric(df[col], errors="coerce").dropna()
        if len(series) < 10:
            continue
 
        Q1  = series.quantile(0.25)
        Q3  = series.quantile(0.75)
        IQR = Q3 - Q1
 
        lower = Q1 - 1.5 * IQR
        upper = Q3 + 1.5 * IQR
 
        outlier_count = int(((series < lower) | (series > upper)).sum())
 
        if outlier_count > 0:
            results.append({
                "feature":       col,
                "outlier_count": outlier_count,
                "normal_range":  f"{round(lower, 1)} – {round(upper, 1)}",
                "mean":          round(float(series.mean()), 1),
            })
 
    return results
 
 
def _detect_port_scan(df):
    """
    Simple port scan detection:
    If one source IP connects to many different destination ports,
    it might be scanning for open ports.
    Threshold: more than 15 unique destination ports from one IP.
    """
    suspects = []
 
    if "src_ip" not in df.columns or "dst_port" not in df.columns:
        return suspects
 
    grouped = df.groupby("src_ip")["dst_port"].nunique()
    scanners = grouped[grouped > 15]
 
    for ip, port_count in scanners.items():
        suspects.append({
            "src_ip":          str(ip),
            "unique_ports_hit": int(port_count),
            "warning":         "Possible port scan"
        })
 
    return suspects
 
 
def _empty_result(df):
    """Return empty results when there is not enough data."""
    return {
        "anomaly_count":       0,
        "normal_count":        len(df),
        "total_packets":       len(df),
        "anomaly_percentage":  0.0,
        "anomaly_by_protocol": {},
        "features_used":       [],
        "stat_anomalies":      [],
        "anomalous_packets":   [],
        "port_scan_suspects":  [],
        "labels":              [1] * len(df),
        "scores":              [0.0] * len(df),
    }