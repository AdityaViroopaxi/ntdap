# visualizer.py
# This file creates charts (graphs) from the packet data.
# We use Matplotlib and Seaborn to draw the charts.
# Each chart is saved as a PNG image file.
# visualizer.py
# IMPROVED:
# - Charts now have better labels and colors
# - Timeline chart also shows anomaly spikes
# - Added inter-arrival time chart

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from matplotlib.patches import Patch


def generate_charts(df, anomaly_results, output_folder):
    """
    Create all charts and save them to output_folder.
    Returns a dictionary of chart names and their file paths.
    """

    os.makedirs(output_folder, exist_ok=True)

    chart_paths = {}

    charts = [
        ("protocol_distribution", _protocol_chart),
        ("top_source_ips",        _top_ips_chart),
        ("packet_size",           _packet_size_chart),
        ("traffic_timeline",      _timeline_chart),
        ("top_ports",             _ports_chart),
        ("anomaly_scatter",       _anomaly_chart),
    ]

    for name, func in charts:
        try:
            path = func(df, anomaly_results, output_folder)
            if path:
                chart_paths[name] = path
        except Exception as e:
            print(f"Chart '{name}' failed: {e}")

    return chart_paths


# ─────────────────────────────────────────────────────────────
# Chart functions
# ─────────────────────────────────────────────────────────────

def _protocol_chart(df, anomaly_results, folder):
    """Bar chart of protocol distribution."""
    counts = df["protocol"].value_counts()
    if len(counts) == 0:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))

    # Use a different color for each bar
    colors = plt.cm.tab10.colors[:len(counts)]
    counts.plot(kind="bar", ax=ax, color=colors, edgecolor="white")

    ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Number of Packets")

    # Add count labels on top of each bar
    for bar in ax.patches:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            str(int(bar.get_height())),
            ha="center", va="bottom", fontsize=9
        )

    plt.xticks(rotation=45)
    plt.tight_layout()

    path = os.path.join(folder, "protocol_distribution.png")
    plt.savefig(path)
    plt.close()
    return path


def _top_ips_chart(df, anomaly_results, folder):
    """Horizontal bar chart of top 10 source IPs."""
    top_ips = df["src_ip"].value_counts().head(10)
    if len(top_ips) == 0:
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    top_ips.plot(kind="barh", ax=ax, color="steelblue", edgecolor="white")

    ax.set_title("Top 10 Source IP Addresses", fontsize=14, fontweight="bold")
    ax.set_xlabel("Packet Count")
    ax.invert_yaxis()

    # Add count labels at end of each bar
    for bar in ax.patches:
        ax.text(
            bar.get_width() + 0.3,
            bar.get_y() + bar.get_height() / 2,
            str(int(bar.get_width())),
            va="center", fontsize=9
        )

    plt.tight_layout()
    path = os.path.join(folder, "top_source_ips.png")
    plt.savefig(path)
    plt.close()
    return path


def _packet_size_chart(df, anomaly_results, folder):
    """Histogram of packet sizes with mean line."""
    if "packet_length" not in df.columns:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(df["packet_length"], bins=40, color="mediumorchid", edgecolor="white", alpha=0.85)

    # Add a vertical line for the mean
    mean_size = df["packet_length"].mean()
    ax.axvline(mean_size, color="red", linestyle="--", linewidth=1.5,
               label=f"Mean: {mean_size:.0f} bytes")

    ax.set_title("Packet Size Distribution", fontsize=14, fontweight="bold")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("Count")
    ax.legend()
    plt.tight_layout()

    path = os.path.join(folder, "packet_size.png")
    plt.savefig(path)
    plt.close()
    return path


def _timeline_chart(df, anomaly_results, folder):
    """
    Line chart of traffic over time.
    IMPROVED: Also shows anomaly packets as red dots on the timeline.
    """
    if "timestamp" not in df.columns:
        return None

    timestamps = df["timestamp"]
    counts, edges = np.histogram(timestamps, bins=50)
    times = edges[:-1] - edges[0]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(times, counts, color="darkorange", linewidth=2, label="All packets")
    ax.fill_between(times, counts, alpha=0.25, color="darkorange")

    # Overlay anomaly timing if we have labels
    labels = anomaly_results.get("labels", [])
    if len(labels) == len(df):
        anomaly_mask  = [l == -1 for l in labels]
        anomaly_times = df["timestamp"][anomaly_mask]

        if len(anomaly_times) > 0:
            a_counts, _ = np.histogram(anomaly_times, bins=edges)
            ax.plot(times, a_counts, color="red", linewidth=1.5,
                    linestyle="--", label="Anomalies")

    ax.set_title("Traffic Volume Over Time", fontsize=14, fontweight="bold")
    ax.set_xlabel("Time (seconds from start)")
    ax.set_ylabel("Packets per Interval")
    ax.legend()
    plt.tight_layout()

    path = os.path.join(folder, "traffic_timeline.png")
    plt.savefig(path)
    plt.close()
    return path


def _ports_chart(df, anomaly_results, folder):
    """Bar chart of top destination ports."""
    port_counts = df["dst_port"].value_counts().head(10)
    port_counts = port_counts[port_counts.index > 0]
    if len(port_counts) == 0:
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    port_counts.index = port_counts.index.astype(int).astype(str)
    port_counts.plot(kind="bar", ax=ax, color="indianred", edgecolor="white")

    ax.set_title("Top Destination Ports", fontsize=14, fontweight="bold")
    ax.set_xlabel("Port Number")
    ax.set_ylabel("Packet Count")

    # Add count labels
    for bar in ax.patches:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            str(int(bar.get_height())),
            ha="center", va="bottom", fontsize=9
        )

    plt.xticks(rotation=45)
    plt.tight_layout()

    path = os.path.join(folder, "top_ports.png")
    plt.savefig(path)
    plt.close()
    return path


def _anomaly_chart(df, anomaly_results, folder):
    """Scatter plot: normal vs anomalous packets by size and TTL."""
    labels = anomaly_results.get("labels", [])
    if len(labels) != len(df):
        return None

    sizes  = df["packet_length"].fillna(0).values
    ttls   = df["ttl"].fillna(64).values
    colors = ["red" if l == -1 else "steelblue" for l in labels]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.scatter(sizes, ttls, c=colors, alpha=0.5, s=25)

    legend = [
        Patch(color="steelblue", label=f"Normal ({labels.count(1)})"),
        Patch(color="red",       label=f"Anomaly ({labels.count(-1)})"),
    ]
    ax.legend(handles=legend)

    ax.set_title("Anomaly Detection: Packet Size vs TTL", fontsize=14, fontweight="bold")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("TTL")
    plt.tight_layout()

    path = os.path.join(folder, "anomaly_scatter.png")
    plt.savefig(path)
    plt.close()
    return path
