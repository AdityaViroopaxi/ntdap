# NTDAP v2.0  
## Network Traffic Detection and Analysis Platform with AI Integration

---

## 1. Introduction

NTDAP v2.0 (Network Traffic Detection and Analysis Platform) is a backend-driven analytical system designed to process network packet capture (PCAP) files and generate structured, interpretable, and intelligent insights.

The system integrates data engineering, machine learning, and generative AI to convert raw packet-level binary data into actionable cybersecurity intelligence. It aims to reduce the complexity of manual packet inspection and enhance the efficiency of network threat detection.

---

## 2. Problem Statement

Traditional network analysis tools require manual inspection of packets, making the process:

- Time-consuming  
- Error-prone  
- Difficult for large datasets  
- Lacking automated intelligence  

There is a need for a system that can:
- Automatically analyze network traffic  
- Detect anomalies without labeled data  
- Provide meaningful interpretation  
- Assist analysts with intelligent recommendations  

---

## 3. Objectives

- Automate network traffic analysis  
- Detect anomalous patterns using machine learning  
- Generate statistical and visual insights  
- Provide AI-driven interpretation of network behavior  
- Reduce dependency on manual packet inspection tools  

---

## 4. Installation and Setup Guide

### 4.1 Prerequisites

Ensure the following software is installed:

- Python (version 3.8 or higher)  
- pip (Python package manager)  
- Git  
- Wireshark (optional, for compatibility with PCAP files)  

---

### 4.2 Clone the Repository

```bash
git clone <repository-url>
cd ntdap/backend
4.3 Create Virtual Environment
python -m venv venv

Activate:

Windows:

venv\Scripts\activate

Linux/Mac:

source venv/bin/activate
4.4 Install Dependencies
pip install -r requirements.txt

Manual installation (if needed):

pip install flask flask-cors pandas numpy scapy scikit-learn matplotlib seaborn requests python-dotenv
4.5 Configure Environment Variables

Create .env file:

GEMINI_API_KEY=your_api_key_here

Loaded using:

from dotenv import load_dotenv
import os

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
4.6 Run the Application
python main.py

Server runs at:

http://localhost:5000
5. System Architecture
PCAP Input  
→ Parsing Layer  
→ Data Cleaning Layer  
→ Exploratory Data Analysis  
→ Feature Engineering  
→ Machine Learning (Anomaly Detection)  
→ Visualization Layer  
→ Interpretation Layer  
→ AI Analysis Layer  
→ Output Delivery  
6. Methodology

The system follows a structured pipeline where data is transformed across multiple layers:

6.1 Data Acquisition
User uploads PCAP file via frontend
Flask backend receives file through HTTP POST request
File is stored in server directory
6.2 Data Extraction (Parsing)
Uses Scapy to read binary PCAP file
Iterates over each packet
Extracts:
Network layer (IP addresses)
Transport layer (TCP/UDP ports)
Packet metadata (length, timestamp)
Control flags (TCP flags)
6.3 Data Preprocessing
Remove duplicate packets
Handle missing values
Normalize fields
Convert raw packet data into structured DataFrame
6.4 Feature Engineering
Select numerical attributes
Derive statistical metrics
Prepare dataset for ML model
6.5 Statistical Analysis
Total packets and bytes
Protocol distribution
Top communicating IPs
Traffic intensity (packets/sec)
6.6 Machine Learning
Uses Isolation Forest algorithm
Detects anomalies without labeled data
Identifies unusual traffic patterns
6.7 Visualization
Graphical representation of:
Protocol distribution
Packet sizes
Anomaly distribution
6.8 Interpretation
Rule-based logic applied
Assigns severity levels
Generates textual summary
6.9 AI Analysis
Constructs structured prompt
Sends data to Gemini API
Generates detailed security insights
6.10 Output Delivery
Aggregates all results
Returns JSON response
Displays in frontend
7. Detailed Step-by-Step Execution Flow
User uploads PCAP file
File is saved on server
Parser reads and extracts packet data
Cleaner processes dataset
EDA computes statistical metrics
ML model identifies anomalies
Visualizer generates charts
Interpreter produces summary
AI generates full report
Results displayed to user
8. Technologies Used and Their Role
8.1 Python

Primary programming language used for:

Backend development
Data processing
Machine learning integration
8.2 Flask
Lightweight web framework
Handles API endpoints:
/upload
/ai-analyze
Manages request-response cycle
Acts as communication layer between frontend and backend
8.3 Scapy
Packet manipulation and parsing library
Reads PCAP files using rdpcap
Extracts protocol layers:
Ethernet
IP
TCP/UDP
Provides low-level access to packet data
8.4 Pandas
Data analysis library
Stores packet data in tabular format (DataFrame)
Enables:
Filtering
Aggregation
Transformation
Statistical operations
8.5 NumPy
Supports numerical operations
Used for:
Array manipulation
Mathematical computations
ML feature handling
8.6 Scikit-learn
Machine learning library
Implements Isolation Forest algorithm
Performs:
Model training
Prediction
Anomaly detection
8.7 Matplotlib
Low-level plotting library
Used for generating static graphs
Provides control over chart rendering
8.8 Seaborn
Built on Matplotlib
Simplifies statistical visualization
Produces more readable and aesthetic plots
8.9 Gemini API (Google Generative AI)
Large Language Model (LLM)
Converts structured data into:
Human-readable reports
Threat assessments
Security recommendations
Enhances interpretability of results
8.10 python-dotenv
Loads environment variables from .env
Prevents hardcoding sensitive data
Ensures secure API key management
8.11 Logging Module
Tracks execution flow
Helps debugging and monitoring
Suppresses unnecessary warnings (e.g., Scapy manuf warning)
9. Data Transformation Pipeline
Raw PCAP (Binary Data)
→ Parsed Packets (Structured Records)
→ Cleaned Dataset
→ Statistical Features
→ Machine Learning Features
→ Anomaly Detection
→ Visualization
→ Interpretation
→ AI Intelligence
→ Final Output
10. Key Design Decisions
Modular architecture for maintainability
Use of unsupervised learning (no labeled data required)
Separation of statistical and AI layers
Secure configuration using environment variables
Visualization for enhanced understanding
11. Error Handling
Input validation for uploaded files
Exception handling across modules
API error handling
Timeout handling for AI requests
12. Challenges Addressed
Handling large-scale PCAP data
Missing and inconsistent packet attributes
Feature selection for ML
API quota and latency issues
Data normalization across protocols
13. Limitations
Dependent on quality of PCAP input
Requires internet for AI analysis
No real-time packet capture
Limited deep protocol inspection
14. Future Enhancements
Real-time traffic monitoring
Deep packet inspection (DNS, HTTP, TLS)
Attack classification (DoS, MITM, brute force)
Dashboard-based visualization
Cloud deployment and scalability
15. Conclusion

NTDAP v2.0 demonstrates a complete pipeline that transforms raw network traffic into structured, interpretable, and intelligent insights.

By integrating data processing, machine learning, and AI, the system significantly improves the efficiency and effectiveness of network security analysis.