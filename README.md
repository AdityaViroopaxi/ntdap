# NTDAP v2.0  
## Network Traffic Detection and Analysis Platform with AI Integration

---

## 1. Overview

NTDAP v2.0 is a modular backend system designed to analyze network packet capture (PCAP) files and generate structured insights using data processing, machine learning, and large language model integration.

The system transforms low-level packet data into high-level, actionable intelligence for network security analysis.

---

## 2. System Objectives

- Automate network packet analysis
- Detect anomalous traffic behavior using machine learning
- Generate statistical and visual insights
- Provide AI-driven security interpretation
- Reduce manual dependency on traditional packet analysis tools

---

## 3. System Architecture

PCAP Input → Parsing Layer → Data Cleaning Layer → Exploratory Data Analysis → Machine Learning → Visualization → Interpretation → AI Analysis → Output

---

## 4. Installation Guide

### 4.1 Clone the Repository

git clone <repository-url>
cd ntdap/backend

### 4.2 Create Virtual Environment

python -m venv venv  
venv\Scripts\activate

### 4.3 Install Dependencies

pip install -r requirements.txt

### 4.4 Environment Configuration

Create `.env` file:

GEMINI_API_KEY=your_api_key_here

### 4.5 Run the Server

python main.py

Server runs at http://localhost:5000

---

## 5. Workflow Summary

1. Upload PCAP file  
2. Parse packets into structured data  
3. Clean dataset  
4. Generate statistics  
5. Detect anomalies using ML  
6. Create visualizations  
7. Generate interpretation  
8. Produce AI report  

---

## 6. Conclusion

NTDAP v2.0 converts raw packet data into actionable security insights using a structured pipeline of data processing, machine learning, and AI.
