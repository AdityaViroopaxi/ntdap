

````markdown
# NTDAP v2.0  
## Network Traffic Detection and Analysis Platform with AI Integration

---

## 1. Introduction

NTDAP v2.0 (Network Traffic Detection and Analysis Platform) is a backend-driven analytical system designed to process network packet capture (PCAP) files and generate structured insights using data processing, machine learning, and generative AI.

The system transforms low-level packet-level binary data into high-level, actionable intelligence for cybersecurity analysis.

---

## 2. Problem Statement

Traditional network analysis tools require manual inspection of packets, making the process:

- Time-consuming  
- Error-prone  
- Difficult for large datasets  
- Lacking automated intelligence  

This project automates analysis and integrates machine learning with AI-driven interpretation.

---

## 3. Objectives

- Automate network traffic analysis  
- Detect anomalies using machine learning  
- Generate statistical and visual insights  
- Provide AI-based interpretation  
- Reduce manual effort  

---

## 4. Installation and Setup Guide

### 4.1 Prerequisites

- Python 3.8 or higher  
- pip  
- Git  
- Wireshark (optional)  

---

### 4.2 Clone Repository

```bash
git clone <repository-url>
cd ntdap/backend
````

---

### 4.3 Create Virtual Environment

```bash
python -m venv venv
```

Activate:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/Mac**

```bash
source venv/bin/activate
```

---

### 4.4 Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available:

```bash
pip install flask flask-cors pandas numpy scapy scikit-learn matplotlib seaborn requests python-dotenv
```

---

### 4.5 Configure Environment Variables

Create a `.env` file inside the backend folder:

```
GEMINI_API_KEY=your_api_key_here
```

Used in code:

```python
from dotenv import load_dotenv
import os

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
```

---

### 4.6 Run Application

```bash
python main.py
```

Server runs at:

```
http://localhost:5000
```

---

### 4.7 Verify Installation

Open:

```
http://localhost:5000
```

---

## 5. System Architecture

```
PCAP Input
→ Parsing Layer
→ Data Cleaning Layer
→ Exploratory Data Analysis
→ Feature Engineering
→ Machine Learning (Anomaly Detection)
→ Visualization Layer
→ Interpretation Layer
→ AI Analysis Layer
→ Output
```

---

## 6. Methodology

### Step 1: Data Acquisition

* Upload PCAP file
* Backend receives and stores file

### Step 2: Parsing

* Scapy reads packets
* Extracts IP, ports, protocol, size

### Step 3: Cleaning

* Remove duplicates
* Handle missing values

### Step 4: Feature Engineering

* Select numerical features
* Prepare for ML

### Step 5: Statistical Analysis

* Packet count
* Protocol distribution
* Traffic rate

### Step 6: Machine Learning

* Isolation Forest
* Detect anomalies

### Step 7: Visualization

* Generate charts

### Step 8: Interpretation

* Assign severity
* Generate summary

### Step 9: AI Analysis

* Generate insights using Gemini

---

## 7. Execution Flow

1. Upload PCAP
2. Parse packets
3. Clean data
4. Analyze statistics
5. Detect anomalies
6. Generate charts
7. Interpret results
8. AI generates report
9. Display output

---

## 8. Technologies Used and Their Role

### Python

Core backend language for data processing and logic.

### Flask

Handles API routing and request-response cycle.

### Scapy

Parses PCAP files and extracts packet-level data.

### Pandas

Processes structured data using DataFrames.

### NumPy

Supports numerical operations for ML.

### Scikit-learn

Implements Isolation Forest for anomaly detection.

### Matplotlib

Generates visualization charts.

### Seaborn

Enhances statistical visualizations.

### Gemini API

Generates AI-based insights and reports.

### python-dotenv

Manages environment variables securely.

### Logging

Handles debugging and runtime tracking.

---

## 9. Data Transformation Pipeline

```
Raw PCAP
→ Structured Data
→ Clean Data
→ Statistical Features
→ ML Processing
→ Anomaly Detection
→ Visualization
→ Interpretation
→ AI Analysis
→ Final Output
```

---

## 10. Key Design Decisions

* Modular architecture
* Unsupervised ML approach
* Separation of processing and AI layers
* Secure configuration
* Visualization support

---

## 11. Error Handling

* File validation
* Exception handling
* API validation
* Timeout handling

---

## 12. Challenges

* Large PCAP handling
* Missing packet data
* Feature selection
* API quota issues

---

## 13. Limitations

* Requires valid PCAP
* Depends on AI API
* No real-time capture
* Limited deep inspection

---

## 14. Future Enhancements

* Real-time monitoring
* Deep packet inspection
* Attack classification
* Dashboard UI
* Cloud deployment

---

## 15. Conclusion

NTDAP v2.0 transforms raw network traffic into structured and intelligent insights using machine learning and AI.

---


```
