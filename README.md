# NTDAP v2.0 — Network Traffic Data Analysis Platform

A professional-grade PCAP analysis platform with **Gemini AI-powered** security insights, ML anomaly detection, and 5 detailed result pages.

---

## 🚀 How to Run

### Step 1 — Install Python dependencies

```bash
cd ntdap
pip install -r requirements.txt
```

> On Linux/Mac use `pip3` if `pip` doesn't work.

### Step 2 — Add your Gemini API key

Open `backend/main.py` and find this line near the top:

```python
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"
```

Replace it with your actual key:

```python
GEMINI_API_KEY = "AIza..."   # your key from aistudio.google.com
```

**Get a free Gemini API key at:** https://aistudio.google.com/app/apikey  
(It's free — no credit card needed for Gemini Flash)

### Step 3 — Start the Flask backend

```bash
cd backend
python main.py
```

You should see:
```
Starting NTDAP v2.0 on http://localhost:5000
```

### Step 4 — Open the frontend

Open `frontend/index.html` in your browser.

```bash
# macOS
open frontend/index.html

# Windows
start frontend/index.html

# Linux
xdg-open frontend/index.html
```

Or serve with Python's built-in server:

```bash
cd frontend
python -m http.server 8080
# Visit: http://localhost:8080
```

### Step 5 — Analyze a PCAP file

1. Click **"Upload a PCAP File"**
2. Drop in a `.pcap`, `.pcapng` or `.cap` file
3. Click **"Analyze Traffic"**
4. Browse the 5 result pages — including the **AI Assistant** page

---

## 📂 Project Structure

```
ntdap/
├── backend/
│   ├── main.py              ← Flask server + Gemini AI endpoint
│   ├── modules/
│   │   ├── parser.py        ← PCAP parsing (15+ features/packet)
│   │   ├── cleaner.py       ← Data cleaning
│   │   ├── eda.py           ← Statistics (20+ metrics)
│   │   ├── analyzer.py      ← ML: Isolation Forest + IQR + port scan
│   │   ├── visualizer.py    ← 6 chart types
│   │   └── interpreter.py   ← Plain-English interpretation
│   ├── uploads/             ← Uploaded PCAPs go here
│   └── results/             ← Generated PNG charts go here
│
├── frontend/
│   ├── index.html           ← Landing page
│   ├── upload.html          ← Drag-and-drop upload
│   ├── shared.css           ← Dark theme (shared)
│   ├── nav.js               ← Navigation + helper functions
│   ├── result_overview.html ← Page 1: Summary & severity
│   ├── result_traffic.html  ← Page 2: Protocols, IPs, ports
│   ├── result_security.html ← Page 3: Anomalies & threats
│   ├── result_charts.html   ← Page 4: Charts & packet table
│   └── result_ai.html       ← Page 5: Gemini AI assistant
│
├── demo pcaps/              ← Sample files to test with
└── requirements.txt
```

---

## 📋 Result Pages

| # | Page | Content |
|---|------|---------|
| 1 | Overview | Severity badge, risk score, key stats, recommendation |
| 2 | Traffic | Protocol bars, top IPs with labels, port risk table, communication pairs |
| 3 | Security | Anomalous packet table, port scan alerts, IQR outliers, ML features |
| 4 | Visualizations | All 6 charts with descriptions + 50-packet raw table |
| 5 | AI Assistant | Ask Gemini anything about the traffic — full security report |

---

## 🧪 Demo PCAPs

Files in `demo pcaps/`:
- `demo.pcap` — General mixed traffic (best starting point)
- `divesh.pcapng` — Larger real-world capture
- `udemy-lab*.pcapng` — Focused samples (DNS, DHCP, IPv6, etc.)
