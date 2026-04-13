# interpreter.py
# This file takes the statistics and anomaly results and writes
# a plain-English explanation of what the network traffic looks like.
# No AI API needed — just simple logic and sentence building.
# interpreter.py
# IMPROVED: More detailed analysis including port scan warnings,
# IQR anomaly findings, and private vs public IP commentary.


def interpret(stats, anomaly_results):
    """
    Build a human-readable description of the traffic.
    Returns a dictionary with different sections of the report.
    """

    report = {}

    total    = stats.get("total_packets", 0)
    proto    = stats.get("most_common_protocol", "Unknown")
    src_ip   = stats.get("most_active_src_ip", "Unknown")
    duration = stats.get("capture_duration_seconds", 0)
    pps      = stats.get("packets_per_second", 0)

    # --- Summary ---
    report["summary"] = (
        f"The capture contains {total:,} packets recorded over {duration} seconds "
        f"({pps} packets/second). "
        f"The most common protocol is {proto}. "
        f"The most active sender is {src_ip}."
    )

    # --- Protocol breakdown ---
    protocols = stats.get("protocol_distribution", {})
    lines = []
    for proto_name, count in protocols.items():
        pct = round(count / max(total, 1) * 100, 1)
        lines.append(f"{proto_name}: {count:,} packets ({pct}%)")
    report["protocol_breakdown"] = "Protocol usage: " + ", ".join(lines) + "."

    # --- Packet size ---
    avg  = stats.get("avg_packet_size", 0)
    mini = stats.get("min_packet_size", 0)
    maxi = stats.get("max_packet_size", 0)

    if avg < 200:
        size_note = "Mostly small packets — typical of control messages or ACK-heavy sessions."
    elif avg < 800:
        size_note = "Mixed sizes — combination of interactive and bulk transfer traffic."
    else:
        size_note = "Large average packet size — likely bulk transfers or streaming."

    report["packet_size_analysis"] = (
        f"Sizes range from {mini} to {maxi} bytes, average {avg} bytes. {size_note}"
    )

    # --- Network type (NEW) ---
    private = stats.get("private_ip_count", 0)
    public  = stats.get("public_ip_count", 0)
    if private + public > 0:
        private_pct = round(private / (private + public) * 100, 1)
        if private_pct > 80:
            net_note = f"{private_pct}% internal traffic — mostly LAN communication."
        elif private_pct < 20:
            net_note = f"Mostly external traffic ({100 - private_pct}% public IPs) — internet-facing traffic."
        else:
            net_note = f"Mixed: {private_pct}% internal, {100 - private_pct}% external traffic."
        report["network_type"] = net_note

    # --- Anomaly analysis ---
    count = anomaly_results.get("anomaly_count", 0)
    pct   = anomaly_results.get("anomaly_percentage", 0)

    if count == 0:
        anomaly_text = "No anomalies detected. Traffic appears normal."
    elif pct < 5:
        anomaly_text = (
            f"{count} anomalous packets ({pct}%). "
            "Low rate — likely normal variation."
        )
    elif pct < 15:
        anomaly_text = (
            f"{count} anomalous packets ({pct}%). "
            "Moderate rate — worth reviewing the flagged packets."
        )
    else:
        anomaly_text = (
            f"{count} anomalous packets ({pct}%). "
            "HIGH rate — investigate immediately."
        )

    # Add IQR findings if any (NEW)
    stat_anom = anomaly_results.get("stat_anomalies", [])
    if stat_anom:
        findings = ", ".join([
            f"{s['feature']} ({s['outlier_count']} outliers)"
            for s in stat_anom
        ])
        anomaly_text += f" Statistical outliers found in: {findings}."

    report["anomaly_analysis"] = anomaly_text

    # --- Port scan warning (NEW) ---
    suspects = anomaly_results.get("port_scan_suspects", [])
    if suspects:
        ips = ", ".join([s["src_ip"] for s in suspects])
        report["port_scan_warning"] = (
            f"Possible port scan detected from: {ips}. "
            "These IPs connected to an unusually high number of different ports."
        )

    # --- Severity ---
    if pct < 5:
        report["severity"] = "NORMAL"
    elif pct < 15:
        report["severity"] = "MEDIUM"
    else:
        report["severity"] = "HIGH"

    # Override to HIGH if port scan detected
    if suspects:
        report["severity"] = "HIGH"

    # --- Recommendation ---
    if suspects:
        report["recommendation"] = (
            f"Block or investigate {suspects[0]['src_ip']} — suspected port scanning."
        )
    elif pct > 10:
        report["recommendation"] = (
            "Investigate the anomalous packets listed in the table below."
        )
    else:
        report["recommendation"] = (
            "No immediate action required. Continue regular monitoring."
        )

    return report
