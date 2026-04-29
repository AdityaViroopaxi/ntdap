# interpreter.py — NTDAP v3.0 Advanced Traffic Interpreter
# Generates rich plain-English findings across 8 analysis dimensions.

from datetime import datetime


def interpret(stats: dict, anomaly_results: dict) -> dict:
    report = {}

    total    = stats.get("total_packets", 0)
    proto    = stats.get("most_common_protocol", "Unknown")
    src_ip   = stats.get("most_active_src_ip", "Unknown")
    duration = stats.get("capture_duration_seconds", 0)
    pps      = stats.get("packets_per_second", 0)
    bps      = stats.get("bytes_per_second", 0)

    # ── Executive summary ─────────────────────────────────────────
    report["summary"] = (
        f"Capture of {total:,} packets spanning {duration}s "
        f"({pps} pkt/s · {_fmt_bytes(bps)}/s). "
        f"Dominant protocol: {proto}. "
        f"Most active source: {src_ip}."
    )

    # ── Protocol breakdown ────────────────────────────────────────
    protocols = stats.get("protocol_distribution", {})
    lines = []
    for p_name, count in sorted(protocols.items(), key=lambda x: -x[1]):
        pct = round(count / max(total, 1) * 100, 1)
        lines.append(f"{p_name}: {count:,} ({pct}%)")
    report["protocol_breakdown"] = "Distribution: " + " | ".join(lines[:8]) + "."

    # ── Packet size ───────────────────────────────────────────────
    avg  = stats.get("avg_packet_size", 0)
    mini = stats.get("min_packet_size", 0)
    maxi = stats.get("max_packet_size", 0)
    p95  = stats.get("p95_packet_size", 0)
    if avg < 150:
        size_note = "Predominantly small control frames (ACKs, keepalives)."
    elif avg < 600:
        size_note = "Mixed sizes — interactive sessions and moderate transfers."
    elif avg < 1100:
        size_note = "Mostly full-size frames — bulk file transfer or streaming."
    else:
        size_note = "Very large packets — high-throughput data transfer or jumbo frames."
    report["packet_size_analysis"] = (
        f"Range {mini}–{maxi} bytes | avg {avg} | p95 {p95}. {size_note}"
    )

    # ── Network composition ───────────────────────────────────────
    priv_pct = stats.get("private_pct", None)
    if priv_pct is not None:
        if priv_pct > 85:
            net_note = f"{priv_pct}% internal-only traffic (LAN environment)."
        elif priv_pct < 15:
            net_note = f"Mostly internet-facing traffic ({100-priv_pct}% public IPs)."
        else:
            net_note = f"Mixed network: {priv_pct}% private, {100-priv_pct}% public."
        report["network_type"] = net_note

    # ── Traffic pattern ───────────────────────────────────────────
    iat_ms  = stats.get("avg_inter_arrival_ms", 0)
    flows   = stats.get("unique_flows", 0)
    tcp_cnt = stats.get("tcp_based_count", 0)
    udp_cnt = stats.get("udp_based_count", 0)
    if pps > 1000:
        pattern_note = "HIGH-VOLUME traffic — possible bulk transfer, DDoS, or test generation."
    elif iat_ms < 1:
        pattern_note = "Very rapid bursts — likely automated or high-frequency traffic."
    elif tcp_cnt > udp_cnt * 3:
        pattern_note = "TCP-dominant — connection-oriented sessions (web, file transfer, SSH)."
    elif udp_cnt > tcp_cnt * 3:
        pattern_note = "UDP-dominant — likely streaming, DNS-heavy, or gaming traffic."
    else:
        pattern_note = "Balanced TCP/UDP — general-purpose network usage."
    report["traffic_pattern"] = (
        f"{flows} unique flows | avg IAT {iat_ms}ms. {pattern_note}"
    )

    # ── TCP flag analysis ─────────────────────────────────────────
    syn_c = stats.get("flag_syn_count", 0)
    rst_c = stats.get("flag_rst_count", 0)
    fin_c = stats.get("flag_fin_count", 0)
    if syn_c > 0 or rst_c > 0:
        rst_pct = round(rst_c / max(total, 1) * 100, 1)
        if rst_pct > 10:
            flag_note = f"HIGH RST rate ({rst_pct}%) — connection rejections or scan responses."
        elif syn_c > total * 0.3:
            flag_note = f"Many SYN packets ({syn_c:,}) — high connection-setup rate."
        else:
            flag_note = f"Normal flag mix (SYN:{syn_c:,} RST:{rst_c:,} FIN:{fin_c:,})."
        report["tcp_flag_analysis"] = flag_note

    # ── DNS insights ──────────────────────────────────────────────
    dns_count  = stats.get("dns_query_count", 0)
    dns_unique = stats.get("unique_dns_queries", 0)
    if dns_count > 0:
        top_qs = stats.get("top_dns_queries", {})
        top_list = ", ".join(list(top_qs.keys())[:3])
        report["dns_insights"] = (
            f"{dns_count} DNS queries | {dns_unique} unique domains. "
            f"Top: {top_list}."
        )

    # ── HTTP insights ─────────────────────────────────────────────
    http_cnt = stats.get("http_request_count", 0)
    if http_cnt > 0:
        methods = stats.get("http_methods", {})
        m_list  = " | ".join([f"{k}:{v}" for k,v in methods.items()])
        report["http_insights"] = f"{http_cnt} HTTP requests detected. Methods: {m_list}."

    # ── Anomaly analysis ──────────────────────────────────────────
    a_count = anomaly_results.get("anomaly_count", 0)
    a_pct   = anomaly_results.get("anomaly_percentage", 0)
    features = anomaly_results.get("features_used", [])

    if a_count == 0:
        a_text = "No anomalies detected. Traffic appears normal."
    elif a_pct < 3:
        a_text = f"{a_count:,} anomalies ({a_pct}%) — low rate, likely benign variation."
    elif a_pct < 10:
        a_text = f"{a_count:,} anomalies ({a_pct}%) — moderate. Review flagged packets."
    elif a_pct < 25:
        a_text = f"{a_count:,} anomalies ({a_pct}%) — ELEVATED. Active investigation recommended."
    else:
        a_text = f"{a_count:,} anomalies ({a_pct}%) — CRITICAL. Possible attack or compromise."

    stat_anom = anomaly_results.get("stat_anomalies", [])
    if stat_anom:
        findings = ", ".join([f"{s['feature']} ({s['outlier_count']})" for s in stat_anom])
        a_text += f" Statistical outliers in: {findings}."

    report["anomaly_analysis"] = a_text
    report["features_used"] = f"ML used {len(features)} features: {', '.join(features[:8])}{'...' if len(features)>8 else ''}."

    # ── Threat indicators ─────────────────────────────────────────
    threats = []
    for s in anomaly_results.get("port_scan_suspects", []):
        threats.append(f"PORT-SCAN from {s['src_ip']} ({s['unique_ports_hit']} ports, {s['scan_type']})")
    for s in anomaly_results.get("syn_flood_suspects", []):
        threats.append(f"SYN-FLOOD from {s['src_ip']} ({s['syn_count']} SYN-no-ACK)")
    for s in anomaly_results.get("beaconing_suspects", []):
        threats.append(f"BEACONING {s['src_ip']}→{s['dst_ip']} every ~{s['interval_mean_s']}s")
    for s in anomaly_results.get("dns_tunnel_suspects", []):
        threats.append(f"DNS-TUNNEL hint: {s.get('warning','')}")

    if threats:
        report["threat_indicators"] = threats
    
    suspicious_ports = stats.get("suspicious_port_count", 0)
    if suspicious_ports > 0:
        report["suspicious_ports_note"] = (
            f"{suspicious_ports} packets used known-suspicious ports "
            "(e.g. 4444/Meterpreter, 1337, 31337, 6667/IRC-C2)."
        )

    # ── Severity score ────────────────────────────────────────────
    severity_score = 0
    if a_pct >= 25:    severity_score += 4
    elif a_pct >= 10:  severity_score += 3
    elif a_pct >= 3:   severity_score += 1

    if anomaly_results.get("port_scan_suspects"):  severity_score += 3
    if anomaly_results.get("syn_flood_suspects"):  severity_score += 3
    if anomaly_results.get("beaconing_suspects"):  severity_score += 2
    if anomaly_results.get("dns_tunnel_suspects"): severity_score += 2
    if suspicious_ports > 0:                       severity_score += 2

    if severity_score == 0:
        sev = "NORMAL"
    elif severity_score <= 2:
        sev = "LOW"
    elif severity_score <= 5:
        sev = "MEDIUM"
    elif severity_score <= 8:
        sev = "HIGH"
    else:
        sev = "CRITICAL"

    report["severity"]       = sev
    report["severity_score"] = severity_score

    # ── Recommendation ────────────────────────────────────────────
    if sev == "CRITICAL":
        rec = "IMMEDIATE ACTION: Isolate suspected hosts and perform forensic analysis."
    elif sev == "HIGH":
        rec = "Block or monitor the flagged IPs. Run deep packet inspection on flagged flows."
    elif sev == "MEDIUM":
        rec = "Review anomalous packets table and cross-reference with SIEM alerts."
    elif sev == "LOW":
        rec = "Monitor trending. Schedule a review if anomaly rate increases."
    else:
        rec = "No immediate action required. Continue regular network monitoring."

    report["recommendation"] = rec
    report["analysis_time"]  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return report


def _fmt_bytes(bps: float) -> str:
    if bps < 1024:        return f"{bps:.0f} B"
    if bps < 1024**2:     return f"{bps/1024:.1f} KB"
    return f"{bps/1024**2:.2f} MB"
