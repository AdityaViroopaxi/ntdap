# NTDAP v4.0  
## Network Traffic Data Analysis Platform with AI Integration

---

## 1. Introduction

NTDAP v4.0 (Network Traffic Data Analysis Platform) is a full-stack analytical system designed to process network packet capture (PCAP) files and generate structured insights using data processing, machine learning, and generative AI techniques.

The system focuses on transforming low-level packet-level binary data into high-level, actionable intelligence that can assist in identifying network behavior, detecting anomalies, and supporting cybersecurity analysis. By integrating multiple layers of processing, authentication, persistence, and AI analysis, NTDAP significantly reduces the complexity involved in interpreting raw network traffic.

---

## 2. Problem Statement

Traditional network traffic analysis tools rely heavily on manual inspection of packets, which introduces several limitations:

- The analysis process is time-consuming, especially for large PCAP files  
- Manual inspection increases the chances of human error  
- Identifying patterns in large-scale traffic data is difficult  
- Most tools lack automated intelligence and contextual interpretation  
- Lack of user-based tracking, history, and centralized monitoring  
To address these issues, this project introduces an automated system that combines data processing, machine learning, database persistence, authentication, and AI-driven interpretation to streamline network analysis.

---

## 3. Objectives

The primary objectives of the NTDAP system are:

- To automate the analysis of network traffic data  
- To detect anomalous patterns using machine learning techniques  
- To generate meaningful statistical summaries and visual insights  
- To provide AI-based interpretation of network behavior  
- To implement user authentication and role-based access  
- To maintain per-user analysis history and session tracking  
- To reduce dependency on manual packet inspection methods  

---

## 4. Installation and Setup Guide

### 4.1 Prerequisites

- Python (version 3.8 or higher)  
- pip  
- Git  
- MySQL Server  
- Wireshark (optional)  

---

### 4.2 Clone Repository

```bash
git clone <repository-url>
cd ntdap_v4
```
---
## 4.3 Create Virtual Environment
```
python -m venv venv

Activate:

Windows

venv\Scripts\activate

Linux/Mac

source venv/bin/activate
```
---

## 4.4 Install Dependencies
```
pip install -r requirements.txt
```
---

## 4.5 Configure Environment Variables

### Create a .env file inside the backend folder:

```
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=ntdap_db
GEMINI_API_KEY=your_api_key_here
```
---

## 4.6 Run Application
```
cd backend
python main.py
```
Server runs at:

http://localhost:5000
4.7 Verify Installation

Open:

http://localhost:5000

---

## 5. System Architecture
### PCAP Input
```
→ Parsing Layer
→ Data Cleaning Layer
→ Exploratory Data Analysis
→ Feature Engineering
→ Machine Learning (Anomaly Detection)
→ Visualization Layer
→ Interpretation Layer
→ AI Analysis Layer
→ Database Storage (MySQL)
→ Authentication & Access Control
→ Output (Frontend Dashboard)
```
---

## 6. Methodology

The system follows a structured, multi-stage data processing pipeline where raw network packet data is progressively transformed into meaningful and actionable intelligence.

### Step 1: Data Acquisition

Users upload PCAP files through a frontend interface. The backend validates and securely stores them.

### Step 2: Packet Parsing

Scapy extracts 35+ features including protocol, IPs, ports, flags, payload, entropy, and timing metrics.

### Step 3: Data Cleaning

Handles missing values, duplicates, invalid packets, and normalizes data for ML.

### Step 4: Feature Engineering

Prepares numeric features such as packet size, IAT, flow stats, and entropy for ML models.

### Step 5: Statistical Analysis

Generates insights like:
```
Packet count
Byte volume
Protocol distribution
Top IPs and ports
Traffic rate
```
### Step 6: Machine Learning (Anomaly Detection)

Uses:

Isolation Forest
Local Outlier Factor

Detects anomalies and calculates anomaly percentage.

### Step 7: Visualization

Generates 10 dark-theme charts:

Protocol distribution
Anomaly scatter
Traffic timeline
Heatmaps
Flow analysis
### Step 8: Interpretation

Assigns severity levels (LOW, MEDIUM, HIGH) and produces rule-based insights.

### Step 9: AI-Based Analysis

Gemini AI generates:

Executive summary
Threat assessment
MITRE ATT&CK mapping
Risk score
Recommendations
### Step 10: Persistence & User Management
- Stores sessions in MySQL
- Saves packet-level data and alerts
- Maintains per-user history
Supports admin monitoring
---
## 7. Execution Flow
Upload PCAP
Parse packets
Clean data
Analyze statistics
Detect anomalies
Generate charts
Interpret results
Save to database
AI generates report
Display output

---
## 8. Technologies Used and Their Role

### Python

Python serves as the core programming language for the entire backend system. It is responsible for orchestrating the complete data processing pipeline, including file handling, packet parsing, data transformation, and API communication. Python’s extensive ecosystem of libraries makes it ideal for integrating networking tools (Scapy), data processing (Pandas), and machine learning (Scikit-learn) within a single environment. In this project, Python also handles request routing via Flask and manages communication between different modules such as parser, cleaner, analyzer, and interpreter. Its simplicity and readability enable modular design, making the system easier to maintain and extend.

---

### Flask

Flask is used as the web framework to build the backend API layer of the system. It handles HTTP requests from the frontend, particularly for endpoints such as `/upload` and `/ai-analyze`. Flask processes incoming file uploads, invokes the respective processing pipeline, and returns structured JSON responses. It also manages routing, request parsing, and response formatting. In this project, Flask acts as the bridge between user interaction and backend computation, ensuring smooth communication between the UI and processing modules. Additionally, Flask’s lightweight nature allows for fast execution and easy debugging during development.

---

### Scapy

Scapy is a powerful packet manipulation library used to read and analyze PCAP files. In this project, it is used to parse raw binary packet data using functions like `rdpcap()`. Scapy enables extraction of detailed network-level information such as source IP, destination IP, protocol type, ports, TTL, and TCP flags. It provides access to different protocol layers (Ethernet, IP, TCP/UDP), allowing fine-grained inspection of each packet. The parser module relies heavily on Scapy to iterate through packets and convert them into structured records. Without Scapy, low-level packet decoding would be significantly more complex and error-prone.

---

### Pandas

Pandas is used for structured data processing and analysis. After packet parsing, all extracted packet information is stored in a Pandas DataFrame, which allows efficient manipulation of tabular data. Pandas enables operations such as filtering, grouping, aggregation, and statistical analysis. In this project, it is used in the cleaning stage to remove duplicates and handle missing values, and in the EDA stage to compute metrics such as protocol distribution and top IPs. The DataFrame structure acts as the central data representation throughout the pipeline. This makes it easy to pass processed data between modules while maintaining consistency.

---

### NumPy

NumPy is used for efficient numerical computation and array handling. It supports the mathematical operations required during feature processing and machine learning stages. In this project, NumPy works alongside Pandas to ensure numerical data is properly formatted and optimized for model input. It helps in handling missing numerical values and performing vectorized operations, which improve performance. NumPy arrays are also used internally by Scikit-learn models. Its integration ensures that the anomaly detection algorithm operates efficiently on large datasets.

---

### Scikit-learn

Scikit-learn is used to implement the machine learning component of the system, specifically the Isolation Forest algorithm. Isolation Forest is an unsupervised learning method that identifies anomalies by isolating outliers in the dataset. In this project, Scikit-learn processes numerical features extracted from packet data and trains a model to detect abnormal traffic patterns. It outputs predictions indicating whether each packet is normal or anomalous. The library also provides utilities for preprocessing and model evaluation. Its integration enables automated anomaly detection without requiring labeled training data.

---

### Matplotlib

Matplotlib is used to generate graphical visualizations of network traffic data. It provides the foundational plotting functionality required to create charts such as bar graphs and histograms. In this project, Matplotlib is used to visualize protocol distributions, packet sizes, and anomaly trends. These visualizations help users quickly understand traffic patterns and identify irregular behavior. The charts are generated programmatically and saved as image files. This allows them to be served to the frontend for display.

---

### Seaborn

Seaborn is a high-level visualization library built on top of Matplotlib, used to enhance the aesthetics and readability of charts. It simplifies the creation of statistically meaningful visualizations. In this project, Seaborn is used to create more informative and visually appealing graphs, especially for distributions and correlations. It helps highlight patterns such as skewed traffic or anomaly clusters. By improving visual clarity, it makes it easier for users to interpret results. Seaborn complements Matplotlib by reducing the complexity of plotting code.

---

### Gemini API (Google Generative AI)

The Gemini API is used to integrate a large language model into the system for intelligent analysis. It takes structured outputs such as statistics, anomaly data, and packet samples as input. The system constructs a detailed prompt and sends it to the API. Gemini processes this information and generates a comprehensive natural language report. This includes threat assessment, traffic analysis, recommendations, and a risk score. The AI layer transforms technical data into human-readable insights, making the system accessible to both technical and non-technical users.

---

### python-dotenv

python-dotenv is used to manage environment variables securely. It loads sensitive configuration values such as API keys from a `.env` file instead of hardcoding them into the source code. In this project, it is used to store and access the Gemini API key. This approach improves security and makes the project easier to configure across different environments. It also supports better deployment practices. By separating configuration from code, it enhances maintainability and prevents accidental exposure of sensitive information.

---

### Logging

The logging module is used to monitor the execution flow of the application. It records key events such as parsing progress, analysis steps, and API responses. Logging helps in debugging errors and understanding system behavior during runtime. In this project, it is also used to suppress unnecessary warnings from libraries like Scapy. Structured logs provide visibility into each stage of the pipeline. This makes it easier to diagnose issues and ensure smooth operation of the system.

---
## 9. Data Transformation Pipeline
### Raw PCAP
```
→ Structured Data
→ Clean Data
→ Statistical Features
→ ML Processing
→ Anomaly Detection
→ Visualization
→ Interpretation
→ AI Analysis
→ Database Storage
→ Final Output
```
---

## 10. Key Design Decisions
```
Modular architecture
Unsupervised ML approach
Separation of processing and AI layers
Secure configuration
Role-based authentication
Persistent storage (MySQL)
```
---
## 11. Error Handling
File validation
Exception handling
API validation
Timeout handling
Database failure handling

---
## 12. Challenges
Large PCAP handling
Missing packet data
Feature selection
API quota issues
Synchronizing frontend-backend state

---

## 13. Limitations
Requires valid PCAP
Depends on AI API
No real-time capture
Limited deep inspection

---
## 14. Future Enhancements
- Real-time monitoring
- Deep packet inspection
- Attack classification
- Cloud deployment


---
## 15. Conclusion

NTDAP v4.0 transforms raw network traffic into structured, intelligent, and user-driven insights using machine learning, database systems, authentication, and AI.