# visualizer.py — NTDAP v4.0  (charts encoded as base64 so no CORS issues)
import os, base64, io, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# ── Design tokens (mirror shared.css) ────────────────────────────
BG      = "#030712"
SURFACE = "#0d1117"
SURFACE2= "#161b22"
BORDER  = "#21262d"
ACCENT  = "#00d4ff"
GREEN   = "#10b981"
DANGER  = "#ef4444"
WARN    = "#f59e0b"
PURPLE  = "#7c3aed"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
PALETTE = [ACCENT, PURPLE, GREEN, WARN, DANGER, "#f472b6", "#34d399", "#fbbf24"]

# ── Uniform canvas sizes ──────────────────────────────────────────
SIZE_HALF = (11, 5)   # single-column card
SIZE_FULL = (13, 5)   # wide / full-width card

# ── Shared helpers ────────────────────────────────────────────────
def _style(fig, *axes):
    fig.patch.set_facecolor(BG)
    for ax in axes:
        ax.set_facecolor(SURFACE2)
        ax.tick_params(colors=MUTED, labelsize=8.5)
        ax.xaxis.label.set_color(MUTED)
        ax.yaxis.label.set_color(MUTED)
        ax.title.set_color(TEXT)
        for sp in ax.spines.values():
            sp.set_color(BORDER)
            sp.set_linewidth(0.8)
        ax.grid(color=BORDER, linestyle="--", alpha=0.35, linewidth=0.5)

def _title(ax, text):
    ax.set_title(text, fontsize=11, fontweight="600", color=TEXT, pad=10)

def _b64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.read()).decode()

def _bar_labels(ax, bars, fmt="{:,}", horizontal=False):
    for bar in bars:
        val = bar.get_width() if horizontal else bar.get_height()
        x   = bar.get_width() + 0.3 if horizontal else bar.get_x() + bar.get_width() / 2
        y   = bar.get_y() + bar.get_height() / 2 if horizontal else val + 0.3
        ha  = "left" if horizontal else "center"
        va  = "center" if horizontal else "bottom"
        ax.text(x, y, fmt.format(int(val)), ha=ha, va=va, fontsize=8, color=TEXT)

# ── Chart registry ────────────────────────────────────────────────
def generate_charts(df: pd.DataFrame, anomaly_results: dict, output_folder: str) -> dict:
    os.makedirs(output_folder, exist_ok=True)
    charts = {}
    jobs = [
        ("protocol_distribution", _proto),
        ("top_source_ips",        _top_ips),
        ("packet_size",           _pkt_size),
        ("traffic_timeline",      _timeline),
        ("top_ports",             _ports),
        ("anomaly_scatter",       _scatter),
        ("flow_analysis",         _flow),
        ("tcp_flags",             _flags),
        ("inter_arrival",         _iat),
    ]
    for name, fn in jobs:
        try:
            result = fn(df, anomaly_results)
            if result:
                charts[name] = result
        except Exception as e:
            print(f"[Visualizer] '{name}' skipped: {e}")
    print(f"[Visualizer] {len(charts)} charts generated (base64)")
    return charts

# ── 1  Protocol Distribution ──────────────────────────────────────
def _proto(df, ar):
    counts = df["protocol"].value_counts().head(8)
    if counts.empty: return None
    colors = PALETTE[:len(counts)]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=SIZE_FULL, gridspec_kw={"width_ratios": [1, 1.3]})
    _style(fig, ax1, ax2)
    wedges, _, autotexts = ax1.pie(
        counts, labels=None, colors=colors,
        autopct="%1.1f%%", pctdistance=0.72, startangle=140,
        wedgeprops=dict(width=0.52, edgecolor=BG, linewidth=2))
    for at in autotexts: at.set_fontsize(8.5); at.set_color(TEXT)
    ax1.set_facecolor(BG)
    ax1.legend(counts.index, loc="lower center", ncol=4, fontsize=7.5,
               facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, bbox_to_anchor=(0.5, -0.08))
    _title(ax1, "Protocol Share")
    bars = ax2.barh(counts.index[::-1], counts.values[::-1],
                    color=colors[::-1], edgecolor=BG, linewidth=1.2, height=0.6)
    _bar_labels(ax2, bars, horizontal=True)
    ax2.set_xlim(0, counts.max() * 1.2)
    _title(ax2, "Packet Count by Protocol")
    ax2.set_xlabel("Packets")
    plt.tight_layout(pad=1.8)
    return _b64(fig)

# ── 2  Top Source IPs ─────────────────────────────────────────────
def _top_ips(df, ar):
    ip_pkt  = df["src_ip"].value_counts().head(10)
    ip_byte = df.groupby("src_ip")["packet_length"].sum().nlargest(10)
    common  = ip_pkt.index.intersection(ip_byte.index)[:8]
    if common.empty: return None
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=SIZE_FULL)
    _style(fig, ax1, ax2)
    pkt_vals = ip_pkt.reindex(common)
    bars1 = ax1.barh(common, pkt_vals, color=ACCENT, alpha=0.85, edgecolor=BG, linewidth=1.2, height=0.6)
    ax1.invert_yaxis(); _bar_labels(ax1, bars1, horizontal=True)
    ax1.set_xlim(0, pkt_vals.max() * 1.2)
    _title(ax1, "Top Sources — Packet Count"); ax1.set_xlabel("Packets")
    byte_vals = ip_byte.reindex(common) / 1024
    bars2 = ax2.barh(common, byte_vals, color=PURPLE, alpha=0.85, edgecolor=BG, linewidth=1.2, height=0.6)
    ax2.invert_yaxis(); _bar_labels(ax2, bars2, horizontal=True)
    ax2.set_xlim(0, byte_vals.max() * 1.2)
    _title(ax2, "Top Sources — Traffic (KB)"); ax2.set_xlabel("KB Transferred")
    plt.tight_layout(pad=1.8)
    return _b64(fig)

# ── 3  Packet Size Distribution ───────────────────────────────────
def _pkt_size(df, ar):
    sizes  = df["packet_length"].dropna()
    labels = ar.get("labels", [1] * len(df))
    mask_n = [l == 1  for l in labels[:len(sizes)]]
    mask_a = [l == -1 for l in labels[:len(sizes)]]
    fig, ax = plt.subplots(figsize=SIZE_HALF)
    _style(fig, ax)
    bins = np.linspace(sizes.min(), sizes.max(), 45)
    ax.hist(sizes[mask_n], bins=bins, color=ACCENT, alpha=0.60, label="Normal",  edgecolor=BG, linewidth=0.5)
    ax.hist(sizes[mask_a], bins=bins, color=DANGER, alpha=0.75, label="Anomaly", edgecolor=BG, linewidth=0.5)
    ax.axvline(sizes.mean(),         color=WARN,  linewidth=1.8, linestyle="--", label=f"Mean {sizes.mean():.0f}B")
    ax.axvline(sizes.quantile(0.95), color=GREEN, linewidth=1.4, linestyle=":",  label=f"p95 {sizes.quantile(0.95):.0f}B")
    _title(ax, "Packet Size Distribution")
    ax.set_xlabel("Bytes"); ax.set_ylabel("Count")
    ax.legend(facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    plt.tight_layout(pad=1.5)
    return _b64(fig)

# ── 4  Traffic Timeline ───────────────────────────────────────────
def _timeline(df, ar):
    if "timestamp" not in df.columns: return None
    ts = df["timestamp"]; bins = 60
    edges = np.linspace(ts.min(), ts.max(), bins + 1)
    times = edges[:-1] - edges[0]
    all_c, _ = np.histogram(ts, bins=edges)
    labels = ar.get("labels", [])
    anom_c = np.zeros(bins)
    if len(labels) == len(df):
        anom_ts = df["timestamp"][[l == -1 for l in labels]]
        anom_c, _ = np.histogram(anom_ts, bins=edges)
    fig, ax = plt.subplots(figsize=SIZE_FULL)
    _style(fig, ax)
    ax.fill_between(times, all_c,  alpha=0.15, color=ACCENT)
    ax.plot(times, all_c,  color=ACCENT, linewidth=1.8, label="All traffic")
    ax.fill_between(times, anom_c, alpha=0.25, color=DANGER)
    ax.plot(times, anom_c, color=DANGER, linewidth=1.5, linestyle="--", label="Anomalies")
    _title(ax, "Traffic Volume Over Time")
    ax.set_xlabel("Seconds from capture start"); ax.set_ylabel("Packets / interval")
    ax.legend(facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    plt.tight_layout(pad=1.5)
    return _b64(fig)

# ── 5  Top Destination Ports ──────────────────────────────────────
def _ports(df, ar):
    if "dst_port" not in df.columns: return None
    pc = df[df["dst_port"] > 0]["dst_port"].value_counts().head(12)
    if pc.empty: return None
    RISKY = {4444, 1337, 31337, 12345, 6667, 6666, 9999, 54321}
    PORT_LABELS = {80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",25:"SMTP",3389:"RDP",
                   3306:"MySQL",21:"FTP",8080:"Alt-HTTP",445:"SMB",23:"Telnet",
                   123:"NTP",4444:"Meterpreter"}
    colors  = [DANGER if int(p) in RISKY else PURPLE for p in pc.index]
    xlabels = [f"{int(p)}\n{PORT_LABELS.get(int(p),'')}" for p in pc.index]
    fig, ax = plt.subplots(figsize=SIZE_HALF)
    _style(fig, ax)
    bars = ax.bar(range(len(pc)), pc.values, color=colors, edgecolor=BG, linewidth=1.2, width=0.65)
    ax.set_xticks(range(len(pc)))
    ax.set_xticklabels(xlabels, rotation=0, ha="center", fontsize=7.5, color=MUTED)
    _bar_labels(ax, bars)
    _title(ax, "Top Destination Ports"); ax.set_ylabel("Packet Count")
    ax.legend(handles=[Patch(color=PURPLE,label="Normal"),Patch(color=DANGER,label="Suspicious")],
              facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    plt.tight_layout(pad=1.5)
    return _b64(fig)

# ── 6  Anomaly Scatter ────────────────────────────────────────────
def _scatter(df, ar):
    labels = ar.get("labels", [])
    if len(labels) != len(df): return None
    is_a  = np.array(labels) == -1
    sizes = df["packet_length"].fillna(0).values
    ttls  = df["ttl"].fillna(64).values
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=SIZE_FULL)
    _style(fig, ax1, ax2)
    ax1.scatter(sizes[~is_a], ttls[~is_a], c=ACCENT, alpha=0.30, s=14, label="Normal",  linewidths=0)
    ax1.scatter(sizes[is_a],  ttls[is_a],  c=DANGER, alpha=0.75, s=26, marker="^", label="Anomaly", edgecolors=BG, linewidths=0.4)
    _title(ax1, "Packet Size vs TTL")
    ax1.set_xlabel("Packet Size (bytes)"); ax1.set_ylabel("TTL")
    ax1.legend(facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    if "inter_arrival_time" in df.columns and "payload_ratio" in df.columns:
        iat  = df["inter_arrival_time"].clip(0,1).fillna(0).values
        prat = df["payload_ratio"].fillna(0).values
        ax2.scatter(iat[~is_a], prat[~is_a], c=ACCENT, alpha=0.30, s=14, label="Normal",  linewidths=0)
        ax2.scatter(iat[is_a],  prat[is_a],  c=DANGER, alpha=0.75, s=26, marker="^", label="Anomaly", edgecolors=BG, linewidths=0.4)
        _title(ax2, "Inter-Arrival Time vs Payload Ratio")
        ax2.set_xlabel("IAT (s)"); ax2.set_ylabel("Payload Ratio")
        ax2.legend(facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    plt.tight_layout(pad=1.8)
    return _b64(fig)

# ── 7  Flow Analysis ──────────────────────────────────────────────
def _flow(df, ar):
    avail = [c for c in ["src_ip","dst_ip","src_port","dst_port","protocol"] if c in df.columns]
    if len(avail) < 2: return None
    flows = df.groupby(avail).agg(
        packet_count=("packet_length","count"),
        byte_total=("packet_length","sum")).reset_index()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=SIZE_FULL)
    _style(fig, ax1, ax2)
    ax1.scatter(flows["packet_count"], flows["byte_total"]/1024,
                c=ACCENT, alpha=0.45, s=22, edgecolors=BG, linewidths=0.4)
    try: ax1.set_xscale("log"); ax1.set_yscale("log")
    except: pass
    _title(ax1, "Flow: Packets vs Volume")
    ax1.set_xlabel("Packets per Flow"); ax1.set_ylabel("KB per Flow")
    top_f  = flows.nlargest(10, "byte_total")
    flabels = [f"{r['src_ip'][:13]}→{r['dst_ip'][:13]}" for _, r in top_f.iterrows()]
    bars = ax2.barh(range(len(top_f)), top_f["byte_total"].values/1024,
                    color=PURPLE, alpha=0.85, edgecolor=BG, linewidth=1.2, height=0.65)
    ax2.set_yticks(range(len(top_f))); ax2.set_yticklabels(flabels, fontsize=7.5, color=MUTED)
    ax2.invert_yaxis(); _bar_labels(ax2, bars, horizontal=True)
    _title(ax2, "Top 10 Flows by Volume (KB)"); ax2.set_xlabel("KB")
    plt.tight_layout(pad=1.8)
    return _b64(fig)

# ── 8  TCP Flag Distribution ──────────────────────────────────────
def _flags(df, ar):
    flag_cols = [c for c in ["flag_syn","flag_ack","flag_fin","flag_rst","flag_psh","flag_urg"] if c in df.columns]
    if not flag_cols: return None
    counts = {f.replace("flag_","").upper(): int(df[f].sum()) for f in flag_cols}
    counts = {k: v for k,v in sorted(counts.items(), key=lambda x:-x[1]) if v > 0}
    if not counts: return None
    FCOLORS = {"SYN":ACCENT,"ACK":GREEN,"FIN":PURPLE,"RST":DANGER,"PSH":WARN,"URG":"#f472b6"}
    fig, ax = plt.subplots(figsize=SIZE_HALF)
    _style(fig, ax)
    bars = ax.bar(list(counts.keys()), list(counts.values()),
                  color=[FCOLORS.get(k,MUTED) for k in counts],
                  edgecolor=BG, linewidth=1.2, width=0.55)
    _bar_labels(ax, bars)
    _title(ax, "TCP Flag Distribution"); ax.set_ylabel("Count")
    plt.tight_layout(pad=1.5)
    return _b64(fig)

# ── 9  Inter-Arrival Time ─────────────────────────────────────────
def _iat(df, ar):
    if "inter_arrival_time" not in df.columns: return None
    iat = df["inter_arrival_time"].clip(0, 1).dropna()
    if len(iat) < 5: return None
    fig, ax = plt.subplots(figsize=SIZE_HALF)
    _style(fig, ax)
    ax.hist(iat, bins=55, color=GREEN, alpha=0.70, edgecolor=BG, linewidth=0.5)
    ax.axvline(iat.mean(),         color=WARN,   linewidth=1.8, linestyle="--",
               label=f"Mean {iat.mean()*1000:.1f} ms")
    ax.axvline(iat.quantile(0.99), color=DANGER, linewidth=1.4, linestyle=":",
               label=f"p99 {iat.quantile(0.99)*1000:.1f} ms")
    _title(ax, "Inter-Arrival Time Distribution")
    ax.set_xlabel("Seconds between packets"); ax.set_ylabel("Count")
    ax.legend(facecolor=SURFACE2, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    plt.tight_layout(pad=1.5)
    return _b64(fig)
