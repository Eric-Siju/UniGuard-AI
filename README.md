# UniGuard AI: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![Smart India Hackathon 2026](https://img.shields.io/badge/SIH-2026-blue.svg)](https://www.sih.gov.in/)
[![Problem Statement](https://img.shields.io/badge/Problem%20Statement-SIH26145-orange.svg)](https://www.sih.gov.in/)
[![Passive Mode](https://img.shields.io/badge/Mode-PASSIVE%20READ--ONLY-emerald.svg)]()
[![Model Accuracy](https://img.shields.io/badge/Random%20Forest%20Accuracy-99.8%25%20(Synthetic)-cyan.svg)]()
[![Tests](https://img.shields.io/badge/Tests-24%20Passing-success.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)]()
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript%20%2B%20Vite-blueviolet.svg)]()

> **UniGuard AI** is a competition-grade, offline-first Network Security Monitoring (NSM) and Network Detection and Response (NDR) platform designed specifically for **unidirectional IP traffic** in air-gapped critical infrastructure, operational technology (OT/SCADA), and hardware data diode enclaves.

---

## 1. Problem Statement Overview (SIH26145)

Critical infrastructure facilities, nuclear installations, power grids, and defense command centers use **hardware data diodes** (physical one-way optical fiber links) to isolate protected operational enclaves from outside networks.

However, standard Network Intrusion Detection Systems (NIDS) break down in unidirectional environments because they assume:
- Bidirectional TCP three-way handshakes (`SYN` → `SYN-ACK` → `ACK`)
- Round-trip time (RTT) measurements
- Active interrogation (Nmap scans, banner grabs, ICMP probes)
- Active inline prevention (TCP RST packet injection, connection blocking)
- Decryption of TLS/QUIC payloads

### Mandatory Operational Constraints (Strictly Maintained)
- **PASSIVE MODE:** Zero packets transmitted back into the monitored enclave.
- **READ-ONLY:** The sensor operates as a strictly non-intrusive listener.
- **NO ACTIVE RESPONSE:** Threat detection produces prioritized intelligence for human analyst response; no automated disruptive action.
- **NO PAYLOAD DECRYPTION:** Zero decryption of encrypted payloads; analysis relies on observable headers, timing variance, and Shannon entropy.
- **OFFLINE-FIRST & AIR-GAPPED:** 100% operational locally without requiring internet access or cloud AI dependencies.

---

## 2. Core Upgrades: Professional SOC Capabilities

1. **One-Way Assurance View:** Demarcates application passive enforcement from physical optical data diode deployment.
2. **Multi-Source NSM Log Interoperability:** Ingests and normalizes Zeek JSON logs (`conn.log`, `dns.log`, `ssl.log`) and Suricata EVE JSON (`alert`, `flow`, `dns`, `tls`).
3. **Multi-Signal Consensus Engine:** Correlates 5 detection signals:
   - Deterministic Rule Engine
   - Supervised Random Forest Classifier (100 Trees)
   - Unsupervised Isolation Forest (Anomaly Detector)
   - Behavioral Rolling Baseline Engine (Exponential Moving Averages with `LEARNING` vs `READY` warm-up)
   - Local Offline Threat Intelligence Engine (Zero external egress)
4. **MITRE ATT&CK Mapping:** Automatic mapping of detected threats to ATT&CK tactics and techniques (e.g. `T1046`, `T1071.004`, `T1041`, `T1498`).
5. **Alert Deduplication & Sliding-Window Suppression:** Groups repeated identical events within 60s windows (`Occurrences: 12`, `Suppressed: 11`) to prevent analyst fatigue while preserving evidence.
6. **Explainable Entity Risk Scoring (0–100):** Transparent mathematical scoring based on alert severity, baseline deviations, beacon cadence, and local intel matches.
7. **Passive Asset Inventory:** Automatically tracks observed entities and infers roles (`SERVER`, `CLIENT`, `DNS`, `GATEWAY`, `SUSPICIOUS`) purely from passive flow characteristics.
8. **Attack Campaign Correlation:** Groups separate multi-stage alerts from the same entity into cohesive intrusion campaigns (`Reconnaissance` → `C2` → `DNS Tunneling` → `Exfiltration`).
9. **SOC Case Management:** Full analyst workflow (`NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`), notes logging, alert linking, and plaintext dossier export.
10. **Passive Threat Hunting Console:** Parameterized query console for structured investigation and IP pivoting without executing arbitrary code.
11. **Guided 12-Step Judge Mode:** One-click walkthrough controller built directly into the UI for evaluating judges.

---

## 3. The 6 Required Threat Classes Detected

| Threat Class | Representative Detection Signatures | MITRE ATT&CK |
|---|---|---|
| **1. DDoS Floods** | Abnormal packet velocity (>250 pkts/s), high destination convergence (fan-in), skewed SYN-to-ACK ratios. | T1498 (Network Denial of Service) |
| **2. Botnet C2 Beaconing** | Strict periodic heartbeats with near-zero jitter (IAT std dev < 0.15s), uniform small payloads, fixed C2 endpoints. | T1071 (Application Layer Protocol) |
| **3. DGA / DNS Tunneling** | High Shannon entropy (>3.5 bits) in domain names, excessive query lengths, deep subdomain nesting, hex/base32 encoding. | T1071.004 (DNS) |
| **4. Suspicious Encrypted Traffic** | TLS traffic observed on non-standard ports, automated non-interactive transmission bursts, anomalous packet size sequences. | T1573 (Encrypted Channel) |
| **5. Port Scanning & Reconnaissance** | Horizontal sweeps (>10 hosts), vertical sweeps (>15 ports), rapid cadence (>10 req/s), short uncompleted probes. | T1046 (Network Service Discovery) |
| **6. Data Exfiltration** | Sustained high volumetric outbound egress (>5MB), extreme 15:1+ outbound-to-inbound asymmetry. | T1041 (Exfiltration Over C2 Channel) |

---

## 4. Technology Stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts (compiled into `frontend/dist/` and served directly by FastAPI).
- **Backend:** Python 3.11+ (verified on Python 3.14 on Windows), FastAPI, Pydantic, SQLAlchemy, SQLite, Uvicorn, WebSockets.
- **Detection & ML:** Scikit-learn (RandomForestClassifier, IsolationForest), NumPy, Pandas, Scapy (passive packet inspection).
- **Testing:** Pytest (**24 comprehensive unit & integration tests**, 100% passing).

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

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies if needed
pip install -r backend/requirements.txt
```

### 2. Build the Official Production Frontend
```powershell
# Compile the production React bundle into frontend/dist/
cd frontend
npm run build
cd ..
```

### 3. Launch the Official Production Server
```powershell
# Start FastAPI backend (serves API, WebSockets, and React SPA at port 8000)
.\.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 6. How to Run the Automated Test Suite

```powershell
# From workspace root:
.\.venv\Scripts\python -m pytest -v
```
All **24 tests** will execute covering:
1. `test_zeek_json_ingestion`: Zeek conn.log/dns.log JSON parsing & normalization
2. `test_suricata_eve_ingestion`: Suricata EVE alert/flow/dns JSON parsing
3. `test_local_threat_intel_matching`: Offline threat intel matching (Zero egress)
4. `test_mitre_mapping_in_correlator`: Verification of MITRE ATT&CK technique IDs
5. `test_alert_deduplication`: 60s sliding-window suppression & count tracking
6. `test_entity_risk_scoring`: Transparent 0-100 mathematical risk evaluation
7. `test_case_management`: Case creation, status updates, notes, and report export
8. `test_api_endpoints`: Endpoints for cases, hunt, assets, intel, and data sources
9. `test_health_endpoint`: Passive read-only flag validation
10. `test_shannon_entropy`: Shannon entropy calculation for DNS domains
11. `test_feature_extraction`: 26-dimensional statistical flow feature extraction
12. `test_ddos_rule`: Volumetric SYN flood detection rule
13. `test_port_scan_rule`: Horizontal and vertical port sweep rule
14. `test_botnet_normal_https_does_not_trigger`: Proves normal HTTPS flows do NOT trigger Botnet false positives
15. `test_botnet_synthetic_beacon_sequence_triggers`: Proves periodic beacon sequences DO trigger Botnet C2 alerts
16. `test_dns_tunneling_rule`: High-entropy DNS tunneling detection rule
17. `test_data_exfiltration_rule`: Outbound asymmetric exfiltration detection rule
18. `test_ml_inference_and_anomaly`: Random Forest & Isolation Forest inference
19. `test_csv_parser`: Flexible flow CSV parser validation
20. `test_demo_scenario_whitelist`: Strict whitelist validation for demo scenarios
21. `test_upload_security_validation`: File upload size limits and traversal prevention
22. `test_spa_root_and_fallback`: Single-page application route fallback
23. `test_pcap_parser_and_upload`: Scapy PCAP header parsing without active binaries
24. `test_api_endpoints`: General API functionality

---

## 7. Hardware Benchmark Measurements

*Measured directly on local development hardware (Windows 11, 12 CPU Cores, Python 3.14.0):*
- **Feature Extraction Latency:** `0.015 ms / flow` (p95: `0.026 ms`)
- **Multi-Signal Rule Latency:** `0.010 ms / flow`
- **ML Inference Latency:** `76.359 ms / flow` (100-tree Random Forest + 100-tree Isolation Forest)
- **Total Pipeline Latency:** `76.402 ms / flow`
- **Throughput:** `13.1 flows / sec`
- **Host Resource Utilization:** `187.1 MB RAM`, `9.5% CPU`
- **Status:** *Measured on this development machine (never hardcoded or fabricated).*

---

## 8. Documentation Index

- [Research & References](docs/research.md)
- [Architecture Design](docs/architecture.md)
- [Machine Learning & XAI](docs/ML.md)
- [REST & WebSocket API Reference](docs/API.md)
- [Judge Demonstration Walkthrough](docs/demo.md)
- [Security & One-Way Assurance](docs/security.md)
- [Operational Limitations & Disclaimers](docs/limitations.md)
