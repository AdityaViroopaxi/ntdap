# NTDAP v2.0  
## Network Traffic Data Analysis Platform with AI Integration

---

## 1. Introduction

NTDAP v2.0 (Network Traffic Detection and Analysis Platform) is a backend-driven analytical system designed to process network packet capture (PCAP) files and generate structured insights using data processing, machine learning, and generative AI techniques.

The system focuses on transforming low-level packet-level binary data into high-level, actionable intelligence that can assist in identifying network behavior, detecting anomalies, and supporting cybersecurity analysis. By integrating multiple layers of processing and analysis, NTDAP reduces the complexity involved in interpreting raw network traffic.

---

## 2. Problem Statement

Traditional network traffic analysis tools rely heavily on manual inspection of packets, which introduces several limitations:

- The analysis process is time-consuming, especially for large PCAP files  
- Manual inspection increases the chances of human error  
- Identifying patterns in large-scale traffic data is difficult  
- Most tools lack automated intelligence and contextual interpretation  

These limitations make it challenging to efficiently detect anomalies and potential threats in modern network environments.

To address these issues, this project introduces an automated system that combines data processing, machine learning, and AI-driven interpretation to streamline network analysis.

---

## 3. Objectives

The primary objectives of the NTDAP system are:

- To automate the analysis of network traffic data  
- To detect anomalous patterns using machine learning techniques  
- To generate meaningful statistical summaries and visual insights  
- To provide AI-based interpretation of network behavior  
- To reduce dependency on manual packet inspection methods  

---

## 4. Installation and Setup Guide

### 4.1 Prerequisites

- Python (version 3.8 or higher)  
- pip  
- Git  
- Wireshark (optional)  

---

### 4.2 Clone Repository

```bash
git clone <repository-url>
cd ntdap/backend

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

The system follows a structured, multi-stage data processing pipeline where raw network packet data is progressively transformed into meaningful and actionable intelligence. Each stage in the pipeline performs a specific function, ensuring data is cleaned, analyzed, and enriched before final interpretation.

---

### Step 1: Data Acquisition

In this stage, the user uploads a PCAP or PCAPNG file through the frontend interface. The file is transmitted to the backend using an HTTP POST request handled by the Flask framework. The backend validates the uploaded file to ensure it is not empty and is in the correct format. Once validated, the file is securely stored in the server’s upload directory. This stage acts as the entry point of the system and ensures that raw network traffic data is properly captured for further processing. Proper handling at this stage is critical to avoid corrupted or invalid inputs affecting downstream analysis.

---

### Step 2: Packet Parsing

The parsing stage is responsible for converting raw binary packet data into a structured format. The system uses Scapy to read the PCAP file using functions such as `rdpcap()`. Each packet is iterated sequentially, and relevant information is extracted from different protocol layers. This includes source and destination IP addresses, transport layer ports, protocol type (TCP, UDP, ICMP), packet length, TTL, and TCP flags. The extracted data is stored as a collection of structured records. These records are then converted into a Pandas DataFrame, enabling efficient data manipulation. This step transforms unstructured network data into a usable format for analysis.

---

### Step 3: Data Cleaning

Once the raw packet data is structured, it undergoes a cleaning process to ensure data quality and consistency. Duplicate packets are identified and removed to avoid skewed analysis results. Missing or null values are handled appropriately, either by filling them with default values or excluding incomplete records. Data types are normalized to ensure consistency across all fields. Any malformed or invalid entries are filtered out. This step ensures that the dataset is reliable and suitable for further statistical and machine learning operations. Clean data is essential for accurate anomaly detection and interpretation.

---

### Step 4: Feature Engineering

In this stage, relevant features are selected and prepared for machine learning analysis. Since machine learning models require numerical input, non-numeric fields are either transformed or excluded. Important numerical features such as packet length, port numbers, and timing-related attributes are retained. Additional derived features may also be created if needed to enhance model performance. The dataset is then formatted into a structure compatible with the machine learning algorithm. Feature engineering plays a crucial role in improving the accuracy and effectiveness of anomaly detection.

---

### Step 5: Statistical Analysis

The system performs exploratory data analysis (EDA) to generate key statistical insights about the network traffic. This includes calculating the total number of packets, total bytes transferred, and the duration of the capture. It also computes packet rate (packets per second) to understand traffic intensity. Protocol distribution is analyzed to identify the most commonly used protocols. The system identifies top source IP addresses and frequently targeted destination ports. These statistics provide a high-level overview of network behavior and help identify patterns or irregularities even before applying machine learning.

---

### Step 6: Machine Learning (Anomaly Detection)

The cleaned and processed dataset is then passed to the machine learning module for anomaly detection. The system uses the Isolation Forest algorithm, which is an unsupervised learning technique designed to detect outliers. The model is trained on the dataset to learn normal traffic behavior. It then isolates data points that deviate significantly from the norm, marking them as anomalies. Each packet is assigned a label indicating whether it is normal or anomalous. The system also calculates the percentage of anomalies and identifies suspicious patterns such as port scanning activity. This step enables automated detection of potentially malicious traffic without requiring labeled data.

---

### Step 7: Visualization

To enhance interpretability, the system generates visual representations of the analyzed data. Using Matplotlib and Seaborn, charts such as protocol distribution graphs, packet size histograms, and anomaly plots are created. These visualizations help users quickly understand traffic patterns and identify unusual behavior. The generated charts are saved as image files in the server’s results directory. These images are then made accessible to the frontend for display. Visualization plays a key role in making complex data more understandable and accessible.

---

### Step 8: Interpretation

In this stage, the system applies rule-based logic to interpret the statistical and machine learning results. Based on metrics such as anomaly percentage and traffic patterns, the system assigns a severity level (e.g., LOW, MEDIUM, HIGH). It generates a textual summary describing the overall network behavior. The interpretation module bridges the gap between raw data analysis and human understanding. It provides context to the results, helping users understand whether the observed activity is normal or potentially harmful. This step ensures that the output is meaningful even for users without deep technical expertise.

---

### Step 9: AI-Based Analysis

The final stage involves advanced analysis using a large language model via the Gemini API. The system constructs a detailed prompt by combining statistical data, anomaly results, and sample packet information. This prompt is sent to the AI model, which generates a comprehensive security report. The report includes an executive summary, threat assessment, traffic behavior analysis, recommended actions, and a risk score. This step enhances the system by providing intelligent, context-aware insights. It transforms technical analysis into professional, human-readable conclusions, making the system significantly more powerful and user-friendly.

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

