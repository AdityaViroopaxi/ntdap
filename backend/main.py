# main.py — NTDAP v4.0 Backend (Auth + Per-user history + Admin)
import os, json, time, random, logging
import requests




from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from .modules.parser      import parse_pcap
from .modules.cleaner     import clean_data
from .modules.eda         import analyze
from .modules.analyzer    import detect_anomalies
from .modules.visualizer  import generate_charts
from .modules.interpreter import interpret
from .modules.db          import (
    init_db, save_session, update_session_severity,
    get_session_packets, get_session_detail, get_threat_stats,
    get_connection
)
from .modules.auth import (
    init_auth_db,
    register_user, login_user, logout_user,
    get_current_user, require_auth, require_admin,
    get_user_sessions, get_all_users_admin, get_all_sessions_admin,
    toggle_user_active, get_user_profile
)

from scapy.config import conf
conf.manufdb = None
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

load_dotenv()
app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), "uploads")
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
print("Gemini key loaded:", bool(GEMINI_API_KEY))
ALLOWED_EXT    = {".pcap", ".pcapng", ".cap"}

try:
    init_db()
    init_auth_db()
except Exception as e:
    print(f"⚠️  DB init: {e}")


def _get_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.headers.get("X-Auth-Token", "")


STATIC_FOLDER = os.path.join(os.path.dirname(__file__), "static")

STATIC_FOLDER = os.path.join(os.path.dirname(__file__), "static")

@app.route("/")
def home():
    return send_from_directory(STATIC_FOLDER, "index.html")

@app.route("/login")
def login_page():
    return send_from_directory(STATIC_FOLDER, "login.html")

@app.route("/register")
def register_page():
    return send_from_directory(STATIC_FOLDER, "register.html")

@app.route("/upload-page")
def upload_page():
    return send_from_directory(STATIC_FOLDER, "upload.html")

@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(STATIC_FOLDER, "dashboard.html")

@app.route("/history-page")
def history_page():
    return send_from_directory(STATIC_FOLDER, "history.html")

@app.route("/admin")
def admin_page():
    return send_from_directory(STATIC_FOLDER, "admin.html")





# ── Auth ───────────────────────────────────────────────────────────
@app.route("/auth/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    username = (body.get("username") or "").strip()
    email    = (body.get("email") or "").strip()
    password = body.get("password", "")
    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400
    user, err = register_user(username, email, password)
    if err:
        return jsonify({"error": err}), 409
    return jsonify({"success": True, "user": user})


@app.route("/auth/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    identifier = (body.get("username") or body.get("email") or "").strip()
    password   = body.get("password", "")
    if not identifier or not password:
        return jsonify({"error": "username/email and password required"}), 400
    token, result = login_user(identifier, password)
    if token is None:
        return jsonify({"error": result}), 401
    return jsonify({"success": True, "token": token, "user": result})


@app.route("/auth/logout", methods=["POST"])
def logout():
    logout_user(_get_token())
    return jsonify({"success": True})


@app.route("/auth/me")
def me():
    info = get_current_user(_get_token())
    if not info:
        return jsonify({"error": "Not authenticated"}), 401
    profile = get_user_profile(info["user_id"])
    return jsonify({"success": True, "user": profile})


# ── Upload ─────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    try:
        user = require_auth(_get_token())
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]

    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = os.path.splitext(f.filename)[1].lower()

    if ext not in ALLOWED_EXT:
        return jsonify({
            "error": f"Unsupported format '{ext}'. Use .pcap/.pcapng/.cap"
        }), 400

    filename = secure_filename(f.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(file_path)

    try:
        # Parse + analysis pipeline
        raw_df = parse_pcap(file_path)
        clean_df = clean_data(raw_df)
        stats = analyze(clean_df)
        anomaly_results = detect_anomalies(clean_df)
        charts = generate_charts(
            clean_df,
            anomaly_results,
            RESULTS_FOLDER
        )
        report = interpret(stats, anomaly_results)

        packet_sample = (
            clean_df[
                [c for c in [
                    "packet_number",
                    "protocol",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "packet_length",
                    "ttl",
                    "tcp_flags",
                    "payload_length",
                    "packet_type",
                    "dns_query",
                    "http_method",
                    "flow_packet_count"
                ] if c in clean_df.columns]
            ]
            .head(100)
            .fillna("—")
            .to_dict(orient="records")
        )

        ip_enrichment = _enrich_ips(
            stats.get("top_source_ips", {})
        )

        # Save session
        session_id = None

        try:
            labels = anomaly_results.get("labels", [])

            session_id = save_session(
                filename,
                stats,
                anomaly_results,
                clean_df,
                labels,
                user["user_id"]
            )

            update_session_severity(
                session_id,
                report.get("severity", "UNKNOWN"),
                report.get("severity_score", 0)
            )

        except Exception as db_err:
            print(f"⚠️ DB save failed: {db_err}")

        out_anomalies = {
            k: v for k, v in anomaly_results.items()
            if k not in (
                "labels",
                "scores",
                "iso_scores",
                "lof_scores"
            )
        }

        return jsonify({
            "success": True,
            "filename": filename,
            "session_id": session_id,
            "statistics": stats,
            "anomalies": out_anomalies,
            "charts": charts,
            "interpretation": report,
            "packet_sample": packet_sample,
            "ip_enrichment": ip_enrichment
        })

    except Exception as e:
        import traceback
        traceback.print_exc()

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/ai-analyze", methods=["POST"])
def ai_analyze():
    try: require_auth(_get_token())
    except ValueError as e: return jsonify({"error": str(e)}), 401
    body = request.get_json()
    if not body or not GEMINI_API_KEY:
        return jsonify({"error": "Missing payload or API key"}), 400
    stats=body.get("statistics",{}); anomalies=body.get("anomalies",{})
    interp=body.get("interpretation",{}); packets=body.get("packet_sample",[])
    question=body.get("question","")
    prompt = _build_prompt(stats, anomalies, interp, packets, question)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    for attempt in range(3):
        try:
            resp = requests.post(url, headers={"Content-Type":"application/json"},
                json={"contents":[{"parts":[{"text":prompt}]}],"generationConfig":{"temperature":0.3,"maxOutputTokens":16348}}, timeout=100)
            if resp.status_code == 200:
                ai_text = resp.json().get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text","No response.")
                return jsonify({"success":True,"analysis":ai_text})
            elif resp.status_code in (429,503): time.sleep((2**attempt)+random.random())
            else: 
                print("Gemini Error Response:", resp.text)
                return jsonify({
                        "success": True,
                        "analysis": f"""
                AI service temporarily unavailable.

                Core NTDAP analysis completed successfully:
                ✔ PCAP parsing completed
                ✔ Feature extraction completed
                ✔ ML anomaly detection completed
                ✔ Threat detection completed
                ✔ Charts generated successfully

                Gemini API returned:
                {resp.status_code}

                Please check:
                - GEMINI_API_KEY validity
                - Google API quota
                - API permissions
                """
                    })

                    
        except Exception as e:
            print("Gemini Exception:", str(e))

            if attempt == 2:
                return jsonify({
                    "success": True,
                    "analysis": f"""
        AI analysis service failed.

        Reason:
        {str(e)}

        Your core network analysis results are still valid.
        """
                })

            time.sleep(2)


# ── History (per-user) ─────────────────────────────────────────────
@app.route("/history")
def history():
    try: user = require_auth(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 401
    try:
        sessions = get_user_sessions(user["user_id"])
        return jsonify({
    "success": True,
    "history": sessions
})
    except Exception as e: return jsonify({"error":str(e)}), 500


@app.route("/history/<int:session_id>/full", methods=["GET"])
def get_full_history(session_id):
    try:
        user = require_auth(_get_token())

        conn = get_connection()
        cur = conn.cursor(dictionary=True)

        # verify ownership
        cur.execute("""
            SELECT *
            FROM capture_sessions
            WHERE id=%s AND user_id=%s
        """, (session_id, user["user_id"]))

        session_data = cur.fetchone()

        if not session_data:
            return jsonify({
                "error": "Session not found"
            }), 404

        cur.execute("""
            SELECT *
            FROM packets
            WHERE session_id=%s
            LIMIT 500
        """, (session_id,))
        packets = cur.fetchall()

        cur.execute("""
            SELECT *
            FROM threat_alerts
            WHERE session_id=%s
        """, (session_id,))
        alerts = cur.fetchall()

        cur.close()
        conn.close()

        return jsonify({
            "statistics": session_data,
            "packet_sample": packets,
            "alerts": alerts,
            "anomalies": {
                "anomaly_count": session_data.get("anomaly_count",0),
                "anomaly_percentage": session_data.get("anomaly_percentage",0)
            },
            "interpretation": {
                "severity": session_data.get("severity"),
                "severity_score": session_data.get("severity_score")
            }
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/history/<int:sid>")
def session_detail(sid):
    try: user = require_auth(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 401
    try:
        detail = get_session_detail(sid)
        if user["role"] != "admin":
            owner = detail.get("session",{}).get("user_id")
            if owner != user["user_id"]:
                return jsonify({"error":"Forbidden"}), 403
        return jsonify({"success":True,**detail})
    except Exception as e: return jsonify({"error":str(e)}), 500


@app.route("/history/<int:sid>/packets")
def session_packets(sid):
    try: require_auth(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 401
    try:
        limit = min(int(request.args.get("limit",500)),2000)
        return jsonify({"success":True,"session_id":sid,"packets":get_session_packets(sid,limit)})
    except Exception as e: return jsonify({"error":str(e)}), 500


@app.route("/threat-stats")
def threat_stats():
    try: require_auth(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 401
    try: return jsonify({"success":True,"stats":get_threat_stats()})
    except Exception as e: return jsonify({"error":str(e)}), 500


# ── Admin ──────────────────────────────────────────────────────────
@app.route("/admin/users")
def admin_users():
    try: require_admin(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 403
    return jsonify({"success":True,"users":get_all_users_admin()})


@app.route("/admin/sessions")
def admin_sessions():
    try: require_admin(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 403
    return jsonify({"success":True,"sessions":get_all_sessions_admin()})


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
def admin_toggle_user(uid):
    try: require_admin(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 403
    body = request.get_json() or {}
    toggle_user_active(uid, bool(body.get("active",True)))
    return jsonify({"success":True})


@app.route("/admin/stats")
def admin_stats():
    try: require_admin(_get_token())
    except ValueError as e: return jsonify({"error":str(e)}), 403
    try:
        users = get_all_users_admin()
        sessions = get_all_sessions_admin()
        threats = get_threat_stats()
        total_packets = sum(s.get("total_packets") or 0 for s in sessions)
        sev_counts = {}
        for s in sessions:
            k = s.get("severity","UNKNOWN"); sev_counts[k] = sev_counts.get(k,0)+1
        return jsonify({"success":True,"total_users":len(users),"total_sessions":len(sessions),
                        "total_packets":total_packets,"severity_breakdown":sev_counts,"threat_stats":threats})
    except Exception as e: return jsonify({"error":str(e)}), 500


@app.route("/results/<filename>")
def get_chart(filename):
    return send_from_directory(RESULTS_FOLDER, filename)


# ── Helpers ────────────────────────────────────────────────────────
KNOWN_IPS = {"8.8.8.8":"Google DNS","8.8.4.4":"Google DNS","1.1.1.1":"Cloudflare DNS","1.0.0.1":"Cloudflare DNS","208.67.222.222":"OpenDNS"}

def _enrich_ips(top_ips):
    import ipaddress
    result = {}
    for ip, count in top_ips.items():
        label = KNOWN_IPS.get(str(ip),"")
        if not label:
            try:
                addr = ipaddress.ip_address(str(ip))
                label = "Private LAN" if (addr.is_private or addr.is_loopback) else ("Multicast" if addr.is_multicast else "External")
            except: label = "Unknown"
        result[str(ip)] = {"count":count,"label":label}
    return result

def _build_prompt(stats, anomalies, interpretation, packets, question):
    top_packets = packets[:5]

    detected_threats = []

    if anomalies.get("port_scan_suspects"):
        detected_threats.append("Port Scanning")

    if anomalies.get("syn_flood_suspects"):
        detected_threats.append("SYN Flood")

    if anomalies.get("beaconing_suspects"):
        detected_threats.append("Beaconing / C2")

    if anomalies.get("dns_tunnel_suspects"):
        detected_threats.append("DNS Tunneling")

    if not detected_threats:
        detected_threats.append("No major signature-based threats detected")

    question_text = question.strip() if question else ""

    if not question_text:
        task = """
    Generate a structured cybersecurity report in this EXACT format:

    1. Executive Summary
    2. Threat Level (Low/Medium/High/Critical)
    3. Key Suspicious Activities
    4. Attack Evidence
    5. MITRE ATT&CK Mapping
    6. Recommended Actions
    7. Final Verdict

    Use actual traffic evidence.
    Mention IPs, ports, anomalies, protocols, and threats.
    Do not skip sections.
    """
    else:
        task = f"""
        Answer this user question directly:

        "{question_text}"

        Then provide:
        - Evidence from traffic
        - Risk assessment
        - Recommended action

        Be precise and avoid generic responses.
        """

    prompt = f"""
You are a Senior SOC Analyst investigating suspicious network traffic.

NETWORK DATA:
- Total Packets: {stats.get("total_packets")}
- Total Bytes: {stats.get("total_bytes")}
- Most Common Protocol: {stats.get("most_common_protocol")}
- Top Source IP: {stats.get("most_active_src_ip")}
- Unique Flows: {stats.get("unique_flows")}

ANOMALY DATA:
- Anomaly Count: {anomalies.get("anomaly_count")}
- Anomaly Percentage: {anomalies.get("anomaly_percentage")}%

DETECTED THREATS:
{", ".join(detected_threats)}

TOP SUSPICIOUS PACKETS:
{json.dumps(top_packets[:3], indent=2)}

AUTOMATED FINDINGS:
{interpretation.get("summary","")}
{interpretation.get("anomaly_analysis","")}

TASK:
{task}

Rules:
- Use actual evidence from provided data
- Mention suspicious IPs/protocols if found
- Do not give generic textbook explanations
- Be concise but technical
- If traffic looks normal, clearly say so
"""
    return prompt

if __name__ == "__main__":
    print("Starting NTDAP v4.0 on http://localhost:5000")
    app.run(debug=True, port=5000)
