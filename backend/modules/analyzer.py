# analyzer.py — NTDAP v3.0 Advanced Anomaly Detection Engine
#
# Detection methods (stacked ensemble):
#   1. Isolation Forest (ML) — general multivariate anomaly detection
#   2. Local Outlier Factor  (ML) — density-based local anomalies
#   3. IQR Statistical Outlier — per-feature outlier flagging
#   4. Port Scan Detection     — horizontal + vertical scan heuristics
#   5. SYN Flood Detection     — SYN-no-ACK rate per source IP
#   6. Beaconing Detection     — periodic connection intervals (C2 hint)
#   7. DNS Tunnelling Hint     — unusually large/frequent DNS queries
#
# Final label = majority vote of IF + LOF methods.

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


# ─────────────────────────────────────────────────────────────────
# Feature groups
# ─────────────────────────────────────────────────────────────────
CORE_FEATURES = [
    "packet_length", "payload_length", "ttl", "window_size",
    "src_port", "dst_port", "inter_arrival_time", "payload_ratio",
    "is_private_src", "header_length",
]
EXTENDED_FEATURES = [
    "tcp_flags_value", "flag_syn", "flag_ack", "flag_rst",
    "flow_packet_count", "flow_bytes_total", "flow_duration",
    "log_packet_length", "log_inter_arrival_time", "log_flow_bytes",
    "iat_rolling_std", "syn_no_ack",
    "is_suspicious_port", "is_multicast",
]


def detect_anomalies(df: pd.DataFrame) -> dict:
    if len(df) < 10:
        return _empty_result(df)

    features = [f for f in CORE_FEATURES + EXTENDED_FEATURES if f in df.columns]
    X_raw = df[features].fillna(0).values.astype(float)

    # Scale for LOF (IF is scale-invariant but scale helps LOF)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    # ── Method 1: Isolation Forest ───────────────────────────────
    contamination = _estimate_contamination(df)
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_features=min(len(features), 10),
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled)
    iso_pred   = iso.predict(X_scaled)        # 1=normal, -1=anomaly
    iso_scores = iso.decision_function(X_scaled)

    # ── Method 2: Local Outlier Factor ───────────────────────────
    n_neighbors = min(20, max(5, len(df) // 10))
    lof = LocalOutlierFactor(
        n_neighbors=n_neighbors,
        contamination=contamination,
        n_jobs=-1,
    )
    lof_pred   = lof.fit_predict(X_scaled)    # 1=normal, -1=anomaly
    lof_scores = lof.negative_outlier_factor_

    # ── Ensemble: majority vote ──────────────────────────────────
    # -1 if at least 1 of 2 methods flags it  (OR logic — higher recall)
    # Use AND for stricter: change to sum(==-1) >= 2
    votes  = np.stack([iso_pred, lof_pred], axis=1)
    labels = np.where(votes.sum(axis=1) <= -1, -1, 1)   # OR: any -1 → anomaly

    # Combined score: average of normalised scores
    iso_norm  = (iso_scores - iso_scores.mean()) / (iso_scores.std() + 1e-9)
    lof_norm  = (lof_scores - lof_scores.mean()) / (lof_scores.std() + 1e-9)
    combined  = (iso_norm + lof_norm) / 2.0

    anomaly_count = int((labels == -1).sum())
    total         = len(labels)
    anomaly_pct   = round(anomaly_count / total * 100, 2)

    # ── Anomaly by protocol ───────────────────────────────────────
    df_copy = df.copy()
    df_copy["_anomaly"]  = labels == -1
    df_copy["_score"]    = combined
    anomaly_by_proto = (
        df_copy[df_copy["_anomaly"]]["protocol"]
        .value_counts()
        .to_dict()
    )

    # ── Top anomalous packets table ────────────────────────────────
    cols = ["packet_number", "src_ip", "dst_ip", "protocol",
            "packet_length", "dst_port", "ttl", "tcp_flags", "_score"]
    avail = [c for c in cols if c in df_copy.columns]
    anomalous_packets = (
        df_copy[df_copy["_anomaly"]]
        .nsmallest(15, "_score")[avail]
        .fillna("—")
        .rename(columns={"_score": "anomaly_score"})
        .to_dict(orient="records")
    )
    for p in anomalous_packets:
        if "anomaly_score" in p:
            p["anomaly_score"] = round(float(p["anomaly_score"]), 4)

    # ── Secondary detections ──────────────────────────────────────
    iqr_findings        = _iqr_detection(df)
    port_scan_suspects  = _detect_port_scan(df)
    syn_flood_suspects  = _detect_syn_flood(df)
    beaconing_suspects  = _detect_beaconing(df)
    dns_tunnel_suspects = _detect_dns_tunnelling(df)

    return {
        "anomaly_count":         anomaly_count,
        "normal_count":          total - anomaly_count,
        "total_packets":         total,
        "anomaly_percentage":    anomaly_pct,
        "contamination_estimate": round(contamination, 4),
        "anomaly_by_protocol":   anomaly_by_proto,
        "features_used":         features,
        "stat_anomalies":        iqr_findings,
        "anomalous_packets":     anomalous_packets,
        "port_scan_suspects":    port_scan_suspects,
        "syn_flood_suspects":    syn_flood_suspects,
        "beaconing_suspects":    beaconing_suspects,
        "dns_tunnel_suspects":   dns_tunnel_suspects,
        "labels":                labels.tolist(),
        "scores":                combined.tolist(),
        "iso_scores":            iso_scores.tolist(),
        "lof_scores":            lof_scores.tolist(),
    }


# ─────────────────────────────────────────────────────────────────
# Contamination estimator
# ─────────────────────────────────────────────────────────────────
def _estimate_contamination(df: pd.DataFrame) -> float:
    """
    Heuristically estimate contamination from suspicious indicators.
    Avoids the fixed 0.05 assumption.
    """
    hints = 0
    if "is_suspicious_port" in df.columns:
        hints += df["is_suspicious_port"].sum()
    if "flag_rst" in df.columns:
        hints += df["flag_rst"].sum()
    if "syn_no_ack" in df.columns:
        hints += df["syn_no_ack"].sum()
    n = max(len(df), 1)
    est = min(max(hints / n, 0.02), 0.30)
    return round(est, 4)


# ─────────────────────────────────────────────────────────────────
# IQR Outlier Detection
# ─────────────────────────────────────────────────────────────────
def _iqr_detection(df: pd.DataFrame) -> list:
    results = []
    check = ["packet_length", "ttl", "inter_arrival_time", "window_size",
             "flow_packet_count", "flow_bytes_total"]
    for col in check:
        if col not in df.columns:
            continue
        series = pd.to_numeric(df[col], errors="coerce").dropna()
        if len(series) < 10:
            continue
        Q1, Q3 = series.quantile(0.25), series.quantile(0.75)
        IQR = Q3 - Q1
        if IQR == 0:
            continue
        lo, hi = Q1 - 1.5 * IQR, Q3 + 1.5 * IQR
        n_out = int(((series < lo) | (series > hi)).sum())
        if n_out > 0:
            results.append({
                "feature":       col,
                "outlier_count": n_out,
                "normal_range":  f"{round(lo,1)} – {round(hi,1)}",
                "mean":          round(float(series.mean()), 2),
                "median":        round(float(series.median()), 2),
            })
    return results


# ─────────────────────────────────────────────────────────────────
# Port Scan Detection (horizontal + vertical)
# ─────────────────────────────────────────────────────────────────
def _detect_port_scan(df: pd.DataFrame) -> list:
    suspects = []
    if "src_ip" not in df.columns or "dst_port" not in df.columns:
        return suspects

    # Horizontal scan: one IP → many different ports on many hosts
    by_src = df.groupby("src_ip").agg(
        unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("dst_ip",   "nunique"),
        total_packets=("packet_number", "count"),
    ).reset_index()

    for _, row in by_src.iterrows():
        ports = int(row["unique_dst_ports"])
        hosts = int(row["unique_dst_ips"])
        if ports > 15 or (ports > 8 and hosts > 3):
            scan_type = "HORIZONTAL" if hosts > 5 else "VERTICAL"
            suspects.append({
                "src_ip":            str(row["src_ip"]),
                "unique_ports_hit":  ports,
                "unique_hosts_hit":  hosts,
                "total_packets":     int(row["total_packets"]),
                "scan_type":         scan_type,
                "warning":           f"Possible {scan_type.lower()} port scan",
            })

    return suspects


# ─────────────────────────────────────────────────────────────────
# SYN Flood Detection
# ─────────────────────────────────────────────────────────────────
def _detect_syn_flood(df: pd.DataFrame) -> list:
    suspects = []
    if "syn_no_ack" not in df.columns or "src_ip" not in df.columns:
        return suspects

    syn_counts = (
        df[df["syn_no_ack"] == 1]
        .groupby("src_ip")
        .size()
        .reset_index(name="syn_count")
    )
    threshold = max(20, len(df) * 0.05)
    for _, row in syn_counts.iterrows():
        if row["syn_count"] >= threshold:
            suspects.append({
                "src_ip":    str(row["src_ip"]),
                "syn_count": int(row["syn_count"]),
                "warning":   "Possible SYN flood — high SYN-without-ACK rate",
            })
    return suspects


# ─────────────────────────────────────────────────────────────────
# Beaconing Detection (regular periodic connections = C2 hint)
# ─────────────────────────────────────────────────────────────────
def _detect_beaconing(df: pd.DataFrame) -> list:
    suspects = []
    if "src_ip" not in df.columns or "dst_ip" not in df.columns:
        return suspects
    if "timestamp" not in df.columns:
        return suspects

    grouped = df.groupby(["src_ip", "dst_ip"])
    for (src, dst), grp in grouped:
        if len(grp) < 6:
            continue
        times = grp["timestamp"].sort_values().values
        iats  = np.diff(times)
        if len(iats) < 5:
            continue
        cv = iats.std() / (iats.mean() + 1e-9)   # coefficient of variation
        # Low CV = very regular intervals = beacon-like
        if cv < 0.15 and iats.mean() > 5:
            suspects.append({
                "src_ip":        str(src),
                "dst_ip":        str(dst),
                "interval_mean_s": round(float(iats.mean()), 2),
                "interval_cv":   round(float(cv), 4),
                "connection_count": len(grp),
                "warning":       "Possible beaconing / C2 (very regular connection intervals)",
            })
    return suspects[:10]   # cap at 10


# ─────────────────────────────────────────────────────────────────
# DNS Tunnelling Hint
# ─────────────────────────────────────────────────────────────────
def _detect_dns_tunnelling(df: pd.DataFrame) -> list:
    suspects = []
    dns_df = df[df["protocol"].isin(["DNS", "MDNS"])].copy()
    if dns_df.empty:
        return suspects

    # Large DNS packets or unusually long query names
    if "packet_length" in dns_df.columns:
        large_dns = dns_df[dns_df["packet_length"] > 512]
        if len(large_dns) > 0:
            suspects.append({
                "type":    "LARGE_DNS_PACKETS",
                "count":   len(large_dns),
                "warning": f"{len(large_dns)} DNS packets > 512 bytes (possible tunnelling)",
            })

    # High DNS query rate from single IP
    if "src_ip" in dns_df.columns:
        by_src = dns_df.groupby("src_ip").size()
        for ip, cnt in by_src.items():
            if cnt > 50:
                suspects.append({
                    "type":    "HIGH_DNS_RATE",
                    "src_ip":  str(ip),
                    "count":   int(cnt),
                    "warning": f"{ip} made {cnt} DNS queries (unusual)",
                })

    return suspects


# ─────────────────────────────────────────────────────────────────
def _empty_result(df: pd.DataFrame) -> dict:
    n = len(df)
    return {
        "anomaly_count": 0, "normal_count": n, "total_packets": n,
        "anomaly_percentage": 0.0, "contamination_estimate": 0.05,
        "anomaly_by_protocol": {}, "features_used": [],
        "stat_anomalies": [], "anomalous_packets": [],
        "port_scan_suspects": [], "syn_flood_suspects": [],
        "beaconing_suspects": [], "dns_tunnel_suspects": [],
        "labels": [1] * n, "scores": [0.0] * n,
        "iso_scores": [0.0] * n, "lof_scores": [0.0] * n,
    }
