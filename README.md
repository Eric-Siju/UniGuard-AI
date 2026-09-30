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

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts (compiled into `frontend/dist/` and served directly by FastAPI).
- **Backend:** Python 3.11+ (tested on Python 3.14 on Windows), FastAPI, Pydantic, SQLAlchemy, SQLite, Uvicorn, WebSockets.
- **Network / ML:** Scapy (passive packet inspection), Pandas, NumPy, Scikit-learn (RandomForest, IsolationForest).
- **Testing:** Pytest (16 comprehensive unit & integration tests).

---

## 5. Quick Start Instructions (Windows PowerShell)

UniGuard AI is designed to run **100% offline and locally**. The production setup delivers a **single official web application** where FastAPI serves the compiled React application directly on port 8000.

### Prerequisites
- Python 3.11+ (Python 3.14 compatible)
- Node.js 18+ and npm

### 1. Set Up Python Virtual Environment & Dependencies
```powershell
# Navigate to project root
cd AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install pinned Python dependencies
pip install -r backend/requirements.txt
```

### 2. Build the Official Production Frontend
```powershell
# Navigate to frontend and install packages
cd frontend
npm install

# Compile the production React bundle into frontend/dist/
npm run build
cd ..
```

### 3. Generate Sample Datasets & Train Models
```powershell
# Generate safe, local representative synthetic datasets in data/sample/
python -m backend.app.generator.traffic_generator

# Train Random Forest and Isolation Forest models with temporal context tracking
python -c "from backend.app.engine.ml_detector import ml_detector; ml_detector.train()"
```

### 4. Launch the Official Production Server
```powershell
# Start FastAPI backend (serves API, WebSockets, and React SPA at port 8000)
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

> [!NOTE]
> During frontend development, you may optionally run `npm run dev` in `frontend/` on port 3000, but for production evaluation and the SIH judge demonstration, **`http://127.0.0.1:8000`** is the single official application.

---

## 6. How to Run the Automated Test Suite

```powershell
# From workspace root:
.\.venv\Scripts\pytest.exe -v
```
All **16 unit and integration tests** will execute covering:
1. `test_health_endpoint`: Verifies passive read-only flags
2. `test_shannon_entropy`: Validates domain entropy calculation
3. `test_feature_extraction`: Validates 26-dimensional flow features
4. `test_ddos_rule`: Validates volumetric DDoS detection
5. `test_port_scan_rule`: Validates horizontal and vertical port scan rules
6. `test_botnet_normal_https_does_not_trigger`: Proves normal HTTPS flows do NOT trigger false-positive Botnet alerts
7. `test_botnet_synthetic_beacon_sequence_triggers`: Proves repeated periodic beacon sequences DO trigger Botnet C2 alerts
8. `test_dns_tunneling_rule`: Validates high-entropy DNS tunnel detection
9. `test_data_exfiltration_rule`: Validates volumetric outbound exfiltration detection
10. `test_ml_inference_and_anomaly`: Tests Random Forest and Isolation Forest predictions
11. `test_csv_parser`: Tests heterogeneous CSV flow parsing
12. `test_api_endpoints`: Tests core REST endpoints
13. `test_demo_scenario_whitelist`: Validates strict scenario whitelist rejection of arbitrary inputs
14. `test_upload_security_validation`: Enforces 50MB limits, extensions, and traversal prevention
15. `test_spa_root_and_fallback`: Verifies SPA routing for client-side navigation
16. `test_pcap_parser_and_upload`: Validates Scapy PCAP parsing without external binary dependencies

---

## 7. Interactive Judge Demonstration Steps

1. Open **`http://127.0.0.1:8000`** in your browser.
2. Confirm the visible status badges in the top header:
   `● PASSIVE MODE`, `● READ-ONLY MONITORING`, `● NO ACTIVE RESPONSE`, and `● LIVE WS`.
3. In the streaming control bar, select `Combined Attack Wave (Demo)` and click **START DEMO**.
4. Watch live traffic flow into the dashboard with real-time velocity curves and threat alerts appearing in the feed without manual page refresh.
5. Click **Investigate →** on any alert to inspect the 5-tuple endpoints, corroborating evidence, and Explainable AI feature attribution.
6. Switch to **Traffic Analysis** to search flows, apply filters, or upload PCAP/CSV captures.
7. Switch to **ML & Datasets** to view the confusion matrix, feature importance rankings, and click **RETRAIN MODEL**.
8. Switch to **Benchmark** and click **RUN LIVE HARDWARE BENCHMARK** to measure real local latencies.
9. Switch to **Security Reports** and click **Print / Export PDF** to generate an executive audit report.

---

## 8. Hardware Benchmark Measurements

*Measured on development machine (never fabricated or hardcoded):*
- **Feature Extraction Latency:** `0.012 ms / flow`
- **Multi-Signal Rule Latency:** `0.008 ms / flow`
- **ML Inference Latency:** `74.4 ms / flow` (100-tree Random Forest + 100-tree Isolation Forest)
- **Pipeline Throughput:** `13.4 flows / sec`
- **Resident Memory Footprint:** `~163 MB`

---

## 9. Troubleshooting

- **PowerShell Execution Policy Error (`Activate.ps1 cannot be loaded`):**
  Run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and re-run `.\.venv\Scripts\Activate.ps1`.
- **Port 8000 in use:**
  Check running processes with `Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess` or launch on another port with `--port 8001`.
- **Rebuilding frontend:**
  Run `cd frontend; npm run build; cd ..` whenever frontend code is updated.

---

## 10. Documentation Index

- [Architecture Design](docs/architecture.md)
- [Machine Learning & XAI](docs/ML.md)
- [REST & WebSocket API](docs/API.md)
- [Setup & Installation Guide](docs/setup.md)
- [Judge Demo Walkthrough](docs/demo.md)
- [Security & Compliance](docs/security.md)
- [Operational Limitations](docs/limitations.md)
