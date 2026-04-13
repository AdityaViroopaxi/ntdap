# main.py — NTDAP v2.0 Backend (Gemini AI)
import os
import json
import time
import random
import requests
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv  # New import

# Import custom modules
from modules.parser      import parse_pcap
from modules.cleaner     import clean_data
from modules.eda         import analyze
from modules.analyzer    import detect_anomalies
from modules.visualizer  import generate_charts
from modules.interpreter import interpret

from scapy.config import conf
conf.manufdb = None
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ── Load Environment Variables ─────────────────────────────────────
load_dotenv()
app = Flask(__name__)
CORS(app)

# ── Configuration ──────────────────────────────────────────────────
UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), "uploads")
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# Key is now pulled from the .env file instead of being hardcoded
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def _gemini_url():
    """Uses the stable 2026 Gemini 3 Flash endpoint."""
    return (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-3-flash-preview:generateContent?key={GEMINI_API_KEY}"
    )

# ─────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return jsonify({"status": "NTDAP v2.0 running — Gemini AI ready"})

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename  = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    try:
        raw_df = parse_pcap(file_path)
        clean_df = clean_data(raw_df)
        stats = analyze(clean_df)
        anomaly_results = detect_anomalies(clean_df)
        charts = generate_charts(clean_df, anomaly_results, RESULTS_FOLDER)

        chart_urls = {
            name: f"/results/{os.path.basename(path)}"
            for name, path in charts.items()
        }

        report = interpret(stats, anomaly_results)

        packet_sample = (
            clean_df[[
                "packet_number", "protocol", "src_ip", "dst_ip",
                "src_port", "dst_port", "packet_length", "ttl", "tcp_flags"
            ]]
            .head(50)
            .fillna("—")
            .to_dict(orient="records")
        )

        ip_enrichment = _enrich_top_ips(stats.get("top_source_ips", {}))

        response = {
            "success":        True,
            "filename":       filename,
            "statistics":     stats,
            "anomalies":      anomaly_results,
            "charts":         chart_urls,
            "interpretation": report,
            "packet_sample":  packet_sample,
            "ip_enrichment":  ip_enrichment,
        }

        response["anomalies"].pop("labels", None)
        response["anomalies"].pop("scores", None)

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ai-analyze", methods=["POST"])
def ai_analyze():
    body = request.get_json()
    if not body or not GEMINI_API_KEY:
        return jsonify({"error": "Missing data or API Key"}), 400

    stats      = body.get("statistics", {})
    anomalies  = body.get("anomalies", {})
    interpret_ = body.get("interpretation", {})
    packets    = body.get("packet_sample", [])
    question   = body.get("question", "")

    prompt = _build_prompt(stats, anomalies, interpret_, packets, question)
    url = _gemini_url()

    # ── Retry Logic for 503 (High Demand) or 429 (Rate Limit) ───────
    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.4,
                        "maxOutputTokens": 2048,
                    }
                },
                timeout=60
            )

            if resp.status_code == 200:
                result = resp.json()
                ai_text = (
                    result.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "Empty response from Gemini.")
                )
                return jsonify({"success": True, "analysis": ai_text})

            elif resp.status_code in [429, 503]:
                # Wait: 2s, 4s, 8s with jitter
                wait = (2 ** attempt) + random.random()
                print(f"API busy ({resp.status_code}). Retrying in {wait:.2f}s...")
                time.sleep(wait)
                continue
            
            else:
                return jsonify({"error": f"Gemini Error {resp.status_code}: {resp.text[:300]}"}), 500

        except Exception as e:
            if attempt == max_retries - 1:
                return jsonify({"error": str(e)}), 500
            time.sleep(2)

    return jsonify({"error": "Max retries exceeded"}), 500

@app.route("/results/<filename>")
def get_chart(filename):
    return send_from_directory(RESULTS_FOLDER, filename)

# ── Helpers ────────────────────────────────────────────────────────
def _build_prompt(stats, anomalies, interpretation, packets, question):
    pkt_text = json.dumps(packets[:10], indent=2)
    base = f"""You are a senior network security analyst. 
Analyze this capture:
STATS: {json.dumps(stats)}
ANOMALIES: {json.dumps(anomalies)}
SAMPLE: {pkt_text}
"""
    if question:
        base += f"\nUSER QUESTION: {question}\n"
    
    base += "\nProvide a detailed report with Executive Summary, Threat Assessment, and Actions."
    return base

def _enrich_top_ips(top_ips_dict):
    KNOWN = {
        "8.8.8.8": "Google DNS", 
        "192.168.": "Private LAN", 
        "127.": "Localhost"
    }
    result = {}
    for ip, count in top_ips_dict.items():
        label = "External"
        for prefix, name in KNOWN.items():
            if str(ip).startswith(prefix):
                label = name
                break
        result[str(ip)] = {"count": count, "label": label}
    return result

if __name__ == "__main__":
    print("Starting NTDAP v2.0 on http://localhost:5000")
    app.run(debug=True, port=5000)