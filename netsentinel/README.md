# 🛡️ NetSentinel — AI-Powered Network Traffic Analyzer & Threat Detector

**An Explainable AI-Assisted Real-Time Network Traffic Analysis Tool**

NetSentinel is a cybersecurity tool that combines live packet capture (like Wireshark) with AI-powered analysis and threat detection. Unlike traditional tools that dump raw packet data, NetSentinel **explains what's happening in plain English**, detects threats using Machine Learning, and provides actionable security recommendations.

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd netsentinel
pip install -r requirements.txt
```

**Mac-specific:** You may need to install libpcap:
```bash
brew install libpcap
```

### 2. Train the ML Model (Optional but Recommended)

Download the UNSW-NB15 dataset:
- **Kaggle:** https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
- **Official:** https://research.unsw.edu.au/projects/unsw-nb15-dataset

Place the CSV files in the `data/` directory, then run:
```bash
python train_model.py
```

This trains Random Forest, XGBoost, and Isolation Forest models and generates SHAP explanations.

### 3. Run the Dashboard

```bash
# Live capture requires sudo for packet sniffing
sudo streamlit run app.py

# Or without sudo (use Demo Mode or file upload)
streamlit run app.py
```

### 4. Open in Browser

Navigate to `http://localhost:8501`

---

## 📁 Project Structure

```
netsentinel/
├── app.py                    # Main Streamlit dashboard
├── train_model.py            # ML model training pipeline
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── utils/
│   ├── __init__.py
│   ├── capture_engine.py     # Packet capture & parsing (Scapy)
│   └── ai_explainer.py       # AI explanation engine + Report generator
├── models/                   # Trained ML models (generated)
│   ├── xgboost.pkl
│   ├── random_forest.pkl
│   ├── isolation_forest.pkl
│   ├── scaler.pkl
│   └── shap_explainer.pkl
├── data/                     # Dataset files (user-provided)
│   └── (place UNSW-NB15 CSVs here)
└── reports/                  # Generated evaluation plots
    ├── model_comparison.png
    ├── confusion_matrices.png
    ├── feature_importance.png
    ├── shap_summary.png
    └── shap_bar.png
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NetSentinel Architecture               │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │  Live Network │───▶│  Scapy       │───▶│  Packet    │ │
│  │  Interface    │    │  Capture     │    │  Parser    │ │
│  └──────────────┘    └──────────────┘    └─────┬──────┘ │
│                                                  │        │
│                              ┌───────────────────┼────┐   │
│                              ▼                   ▼    │   │
│                    ┌──────────────┐    ┌─────────────┐│   │
│                    │  Flow        │    │  IP Geo     ││   │
│                    │  Aggregator  │    │  Locator    ││   │
│                    └──────┬───────┘    └──────┬──────┘│   │
│                           │                   │       │   │
│                           ▼                   ▼       │   │
│              ┌─────────────────────────────────────┐  │   │
│              │       AI Analysis Engine             │  │   │
│              │  ┌───────────┐  ┌────────────────┐  │  │   │
│              │  │ Rule-Based│  │ ML Classifier  │  │  │   │
│              │  │ Detection │  │ (XGBoost/RF)   │  │  │   │
│              │  └───────────┘  └────────────────┘  │  │   │
│              │  ┌───────────┐  ┌────────────────┐  │  │   │
│              │  │ Isolation │  │ SHAP/LIME      │  │  │   │
│              │  │ Forest    │  │ Explainer      │  │  │   │
│              │  └───────────┘  └────────────────┘  │  │   │
│              └──────────────┬──────────────────────┘  │   │
│                             │                         │   │
│                             ▼                         │   │
│              ┌─────────────────────────────────────┐  │   │
│              │    Streamlit Dashboard               │  │   │
│              │  ┌─────────┐ ┌────────┐ ┌────────┐  │  │   │
│              │  │ Packet  │ │ Geo    │ │ Threat │  │  │   │
│              │  │ Monitor │ │ Map    │ │ Alerts │  │  │   │
│              │  └─────────┘ └────────┘ └────────┘  │  │   │
│              │  ┌─────────┐ ┌────────┐ ┌────────┐  │  │   │
│              │  │Analytics│ │Inspector│ │ PDF    │  │  │   │
│              │  │ Charts  │ │  + AI  │ │ Report │  │  │   │
│              │  └─────────┘ └────────┘ └────────┘  │  │   │
│              └─────────────────────────────────────┘  │   │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### Core Capabilities
- **Live Packet Capture** — Real-time packet sniffing using Scapy (Mac/Linux)
- **Protocol Decoding** — Full TCP/UDP/ICMP/ARP/DNS breakdown
- **IP Geolocation** — Maps every IP to country, city, ISP using ip-api.com
- **AI Threat Detection** — Rule-based + ML-based threat scoring
- **Plain English Explanations** — Every packet explained in human-readable language
- **Flow Aggregation** — Groups packets into sessions for pattern detection

### ML & AI
- **Multi-Model Comparison** — Random Forest vs XGBoost vs Isolation Forest
- **Anomaly Detection** — Isolation Forest trained on normal traffic detects zero-day threats
- **Explainable AI (XAI)** — SHAP values explain WHY a packet was flagged
- **Flow Anomaly Detection** — Detects port scans, SYN floods, high-rate traffic

### Dashboard
- **Real-Time Packet Monitor** — Color-coded live packet feed with filtering
- **Analytics Dashboard** — Protocol distribution, top talkers, traffic patterns
- **Geographic Map** — Plotly globe showing traffic origins/destinations
- **AI Packet Inspector** — Deep-dive into any packet with full AI analysis
- **Anomaly Alerts** — Flow-level anomaly detection with recommendations
- **PDF Report Generation** — Forensic analysis report export

---

## 🔬 For the Research Paper

### Suggested Title
*"NetSentinel: An Explainable AI-Assisted Real-Time Network Traffic Analysis and Threat Detection Tool"*

### Paper Structure

1. **Abstract** — Introduce the problem (tools show raw data, not explanations), your solution, key results
2. **Introduction** — Motivation, gap in existing tools, contributions
3. **Related Work** — IDS literature, XAI in cybersecurity, existing tools (Wireshark, Snort, Zeek)
4. **System Architecture** — The pipeline diagram above, component descriptions
5. **Methodology**
   - Dataset (UNSW-NB15)
   - Feature selection and preprocessing
   - Model training (RF, XGBoost, Isolation Forest)
   - Explainability integration (SHAP)
   - Rule-based threat analysis
6. **Implementation** — Technology stack, real-time capture, dashboard design
7. **Evaluation**
   - Classification accuracy (table: RF vs XGBoost vs IF)
   - Per-packet processing latency
   - Qualitative comparison with Wireshark/Snort
   - SHAP analysis results
8. **Results & Discussion**
9. **Conclusion & Future Work**

### Key Novelty Points for Reviewers
1. **Integration novelty** — First open-source tool combining live capture + ML classification + XAI explanations + interactive dashboard
2. **Explainability** — SHAP-based per-packet explanations (most IDS are black boxes)
3. **Usability** — Designed for non-experts, unlike Wireshark which requires deep networking knowledge
4. **Zero-day detection** — Isolation Forest for unseen attack patterns
5. **Forensic reporting** — Automated PDF report generation

### Suggested Conferences/Journals
- IEEE Access (open access, good for tools papers)
- ICCCNT (International Conference on Computing, Communication and Networking Technologies)
- ICICCT (International Conference on ICT)
- Computers & Security (Elsevier)
- Journal of Information Security and Applications

---

## 🔧 Configuration

### Network Interfaces (Mac)
- `en0` — Wi-Fi
- `en1` — Ethernet/Thunderbolt
- `lo0` — Loopback (for testing)

### BPF Filter Examples
- `tcp` — Only TCP packets
- `tcp port 80` — Only HTTP traffic
- `host 8.8.8.8` — Traffic to/from Google DNS
- `not port 22` — Exclude SSH
- `tcp and port 443` — Only HTTPS

---

## 📊 Model Training Results

After running `train_model.py`, you'll find:
- `reports/model_comparison.png` — Accuracy/Precision/Recall/F1 comparison
- `reports/confusion_matrices.png` — Per-model confusion matrices
- `reports/feature_importance.png` — XGBoost top 20 features
- `reports/shap_summary.png` — SHAP beeswarm plot
- `reports/shap_bar.png` — SHAP mean absolute impact

---

## 📄 License

This project is developed for academic/research purposes.

---

## 👤 Author

Built as a Computer Engineering major project — AI-Powered Cybersecurity Tool.
