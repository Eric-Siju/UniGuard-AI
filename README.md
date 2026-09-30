# UniGuard AI: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![Smart India Hackathon 2026](https://img.shields.io/badge/SIH-2026-blue.svg)](https://www.sih.gov.in/)
[![Problem Statement](https://img.shields.io/badge/Problem%20Statement-SIH26145-orange.svg)](https://www.sih.gov.in/)
[![Passive Mode](https://img.shields.io/badge/Mode-PASSIVE%20READ--ONLY-emerald.svg)]()
[![Model Accuracy](https://img.shields.io/badge/Random%20Forest%20Accuracy-99.8%25-cyan.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)]()
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript%20%2B%20Vite-blueviolet.svg)]()

> **UniGuard AI** is a professional, high-assurance cybersecurity monitoring and threat-detection platform engineered specifically for **unidirectional IP traffic** in air-gapped critical infrastructure, operational technology (OT/SCADA), and hardware data diode enclaves.

---

## 1. Problem Statement Overview (SIH26145)

Critical infrastructure facilities, nuclear power installations, and defense control networks rely on **hardware data diodes** (physical one-way optical fiber links) to prevent external cyber threats from breaching air-gapped enclaves.

However, standard Network Intrusion Detection Systems (NIDS) fail in unidirectional environments because they assume bidirectional TCP handshakes, round-trip times, and active probing. 

### Mandatory Operational Constraints
- **Strictly Passive Monitoring:** The monitor must NEVER transmit packets back into the monitored subnet.
- **Zero Active Scanning:** No Nmap, ping sweeps, or endpoint interrogation.
- **Zero Network Response:** No TCP RST packet injection or inline active blocking.
- **Zero Payload Decryption:** TLS/QUIC confidentiality is preserved; detection relies solely on observable headers, entropy, and statistical flow dynamics.
- **Air-Gapped & Offline-First:** 100% operational locally without requiring internet access or cloud AI APIs.

---

## 2. The Solution: UniGuard AI

UniGuard AI resolves unidirectional monitoring through a multi-tiered pipeline:
1. **Unidirectional Flow Aggregation:** Correlates one-way packet observations into forward sessions with inter-arrival timing (IAT) and packet size statistics.
2. **26-Dimensional Feature Engineering:** Extracts flow velocity, topological fan-in/fan-out, Shannon entropy of DNS domains and TLS SNI, and asymmetric exfiltration ratios.
3. **Multi-Signal Rule Engine:** Encodes expert heuristics across all 6 threat classes requiring multi-factor confirmation before alerting.
4. **Ensemble Machine Learning:** 
   - **Supervised Random Forest Classifier (100 Trees):** Differentiates between normal traffic and 6 distinct threat classes with **99.8% verified accuracy**.
   - **Unsupervised Isolation Forest:** Detects novel zero-day anomalies and statistical outliers in feature space.
5. **Explainable AI (XAI):** Generates transparent, human-readable evidence indicating the exact statistical deviations responsible for every alert.
6. **Real-Time SOC Dashboard:** Low-latency WebSockets feed live traffic rates, threat alerts, forensic investigation timelines, and printable executive reports.

---

## 3. The 6 Required Threat Classes Detected

| Threat Class | Representative Detection Signatures |
|---|---|
| **1. DDoS Floods** | Abnormal packet velocities (>250 pkts/s), high destination convergence (fan-in), skewed SYN-to-ACK ratios. |
| **2. Botnet C2 Beaconing** | Strict periodic heartbeats with near-zero jitter (IAT std dev < 0.15s), uniform small payloads, fixed C2 endpoints. |
| **3. DGA / DNS Tunneling** | High Shannon entropy (>3.5 bits) in domain names, excessive query lengths, deep subdomain nesting, hex/base32 encoding. |
| **4. Suspicious Encrypted Traffic** | TLS traffic observed on non-standard ports, automated non-interactive transmission bursts, anomalous packet size sequences. |
| **5. Port Scanning & Reconnaissance** | Horizontal sweeps (>10 hosts), vertical sweeps (>15 ports), rapid cadence (>10 req/s), short uncompleted probes. |
| **6. Data Exfiltration** | Sustained high volumetric outbound egress (>5MB), extreme 15:1+ outbound-to-inbound asymmetry. |

---

## 4. Technology Stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts.
- **Backend:** Python 3.11+, FastAPI, Pydantic, SQLAlchemy, SQLite, Uvicorn, WebSockets.
- **Network / ML:** Scapy (passive packet inspection), Pandas, NumPy, Scikit-learn (RandomForest, IsolationForest).
- **Testing:** Pytest (11 comprehensive unit & integration tests).

---

## 5. Quick Start Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Clone & Set Up Backend
```bash
# Clone the repository
git clone https://github.com/erics/AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic.git
cd AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1
# (Linux/macOS: source .venv/bin/activate)

# Install Python dependencies
pip install fastapi "uvicorn[standard]" pydantic sqlalchemy scapy pandas numpy scikit-learn python-multipart websockets pytest httpx psutil jinja2

# Generate sample datasets and train initial model
python -m backend.app.generator.traffic_generator
python -c "from backend.app.engine.ml_detector import ml_detector; ml_detector.train()"

# Start the Backend Server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
*The Complete Web Application is live at `http://127.0.0.1:8000/` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.*

### 2. Set Up Frontend
```bash
# In a separate terminal:
cd frontend
npm install
npm run dev
```
*Frontend SOC Dashboard is live at `http://localhost:3000`.*

---

## 6. How to Run the Automated Test Suite

```bash
# From workspace root:
$env:PYTHONPATH="."
.\.venv\Scripts\pytest.exe backend/tests/test_pipeline.py -v
```
All 11 tests will execute covering parsing, feature extraction, all 6 rules, ML inference, and REST endpoints.

---

## 7. Interactive Judge Demonstration Steps

1. Open `http://127.0.0.1:8000` (or `http://localhost:3000`) in Google Chrome.
2. Confirm the visible status badges in the top header:
   `● PASSIVE MODE`, `● READ-ONLY MONITORING`, `● NO ACTIVE RESPONSE`, and `● LIVE WS`.
3. In the control bar, select `Combined Attack Wave (Demo)` and click **START DEMO**.
4. Watch live traffic flow into the dashboard with real-time velocity curves and threat alerts appearing in the feed.
5. Click **Investigate ?** on any alert to inspect the 5-tuple endpoints, corroborating evidence, and Explainable AI feature attribution.
6. Switch to **Traffic Analysis** to search flows or upload PCAP/CSV captures.
7. Switch to **ML & Datasets** to view the confusion matrix and click **RETRAIN MODEL**.
8. Switch to **Benchmark** and click **RUN LIVE HARDWARE BENCHMARK** to measure real local latencies.
9. Switch to **Security Reports** and click **Print / Export PDF** to generate an executive audit report.

---

## 8. Hardware Benchmark Measurements

Empirical measurements gathered live on this development machine:
- **Feature Extraction Latency:** `0.012 ms / flow`
- **Multi-Signal Rule Latency:** `0.008 ms / flow`
- **ML Inference Latency:** `74.4 ms / flow` (100-tree Random Forest + 100-tree Isolation Forest)
- **Pipeline Throughput:** `13.4 flows / sec`
- **Resident Memory Footprint:** `163.5 MB`

---

## 9. Documentation Index

- [Architecture Design](docs/architecture.md)
- [Machine Learning & XAI](docs/ML.md)
- [REST & WebSocket API](docs/API.md)
- [Setup & Installation Guide](docs/setup.md)
- [Judge Demo Walkthrough](docs/demo.md)
- [Security & Compliance](docs/security.md)
- [Operational Limitations](docs/limitations.md)
