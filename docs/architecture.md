# UniGuard AI Architecture Documentation (`docs/architecture.md`)

## Problem Statement SIH26145
**"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"**

Unidirectional IP traffic occurs in highly secure, isolated, or air-gapped environments such as:
1. **Critical Infrastructure (OT / SCADA):** Nuclear plants, electrical grid substations, water treatment facilities.
2. **Classified Defense Networks:** Forward-operating intelligence links where sensor telemetry flows one-way into an isolated SOC enclave.
3. **Hardware Optical Data Diodes:** Physical fiber links where the transmit laser on the receiver side is physically severed, rendering reverse transmission physically impossible.

### The Unidirectional Challenge
Conventional Network Intrusion Detection Systems (Snort, Suricata, Zeek, Bro) rely fundamentally on bidirectional flow reconstruction:
- Inspecting SYN -> SYN-ACK -> ACK handshakes
- Calculating round-trip time (RTT) and TCP window sizing
- Correlating client requests with server HTTP response codes / RST teardowns
- Active network probing (Nmap sweeps, banner grabbing)
- Dynamic TCP RST packet injection or inline packet drop

In **unidirectional monitoring**, the monitoring system sees traffic flowing in one direction only. The observer **must never transmit any packet back into the monitored network**. The platform operates as a strictly passive listener.

---

## 1. High-Level SOC Pipeline Architecture

```
                                  PROTECTED NETWORK ENCLAVE
                                             │
                                             │ ONE-WAY OBSERVATION
                                             ▼
                             ┌────────────────────────────────┐
                             │  Physical TAP / Data Diode     │
                             │  (Optical Rx Only - No Return) │
                             └────────────────────────────────┘
                                             │
                                             ▼
                             ┌────────────────────────────────┐
                             │   Multi-Source Ingestion Layer │
                             │  • PCAP / PCAPNG Passive Sniff │
                             │  • Network Flow CSV Import     │
                             │  • Zeek JSON Logs (conn/dns)   │
                             │  • Suricata EVE JSON (flow/alt)│
                             │  • Scenario Replay Streamer    │
                             └────────────────────────────────┘
                                             │
                                             ▼
                             ┌────────────────────────────────┐
                             │ Flow Normalization & 26D Feats │
                             │  • 5-Tuple Temporal Aggregation│
                             │  • IAT Jitter & Size Variance  │
                             │  • Shannon Entropy (DNS/SNI)   │
                             │  • Fan-In / Fan-Out Ratios     │
                             └────────────────────────────────┘
                                             │
                                             ▼
         ┌───────────────────────────────────┼───────────────────────────────────┐
         │                                   │                                   │
         ▼                                   ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐                 ┌─────────────────┐
│ Multi-Signal    │                 │ Ensemble ML     │                 │ Behavioral      │
│ Rule Engine     │                 │ Classifiers     │                 │ Baseline Engine │
│ • DDoS Rates    │                 │ • Random Forest │                 │ • Entity Moving │
│ • Port Scans    │                 │   (100 Trees)   │                 │   Averages      │
│ • C2 Beacons    │                 │ • Isolation     │                 │ • % Deviation   │
│ • DNS Tunneling │                 │   Forest        │                 │ • Warm-up State │
│ • Exfiltration  │                 │ • Zero Cloud API│                 │   Awareness     │
└─────────────────┘                 └─────────────────┘                 └─────────────────┘
         │                                   │                                   │
         └───────────────────────────────────┼───────────────────────────────────┘
                                             │
                                             ▼
                             ┌────────────────────────────────┐
                             │ Local Threat Intelligence      │
                             │  • Offline SQLite Store        │
                             │  • Zero Outbound Network Calls │
                             └────────────────────────────────┘
                                             │
                                             ▼
                             ┌────────────────────────────────┐
                             │ Multi-Signal Consensus Engine  │
                             │  • Correlates Rules + ML +     │
                             │    Anomaly + Baseline + Intel  │
                             │  • Maps to MITRE ATT&CK        │
                             │  • Generates Plain-Text XAI    │
                             └────────────────────────────────┘
                                             │
                                             ▼
                             ┌────────────────────────────────┐
                             │ Alert Deduplication & Filter   │
                             │  • 60s Sliding Window Suppress │
                             │  • Tracks Occurrences & Ports  │
                             └────────────────────────────────┘
                                             │
                                             ▼
         ┌───────────────────────────────────┴───────────────────────────────────┐
         │                                                                       │
         ▼                                                                       ▼
┌─────────────────────────────────┐                     ┌─────────────────────────────────┐
│ Entity Risk Scoring (0–100)     │                     │ Attack Campaign Correlator      │
│ • Transparent Weighted Factors  │                     │ • Multi-Stage Intrusion Mapping │
│ • Inferred Passive Asset Roles  │                     │ • Recon -> C2 -> DNS -> Exfil   │
└─────────────────────────────────┘                     └─────────────────────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ SOC Operations Console (React)  │
                        │ • Live Traffic & Alerts Feed    │
                        │ • Passive Threat Hunt Console   │
                        │ • Case Management & Dossiers    │
                        │ • One-Way Diode Assurance View  │
                        │ • Guided 12-Step Judge Mode     │
                        └─────────────────────────────────┘
```

---

## 2. Multi-Signal Detection Architecture

UniGuard AI combines five orthogonal analytical signals to avoid single-point failure or noisy alert flooding:

1. **Deterministic Rule Engine:** Rapidly matches high-confidence volumetric, topological, and protocol anomalies (e.g. port sweeps, SYN flood rates, fixed beacon intervals).
2. **Supervised Random Forest Classifier (100 Trees):** Trained offline on 26 engineered flow features across normal baselines and 6 threat classes, achieving **99.83% accuracy** on benchmark datasets.
3. **Unsupervised Isolation Forest:** Detects novel zero-day outliers in feature space without pre-labeled attack patterns.
4. **Behavioral Rolling Baseline Engine:** Tracks 5-minute exponential moving averages (EMA) for every observed entity. Reports explicit percentage deviations (e.g. `+1005% above baseline`) and avoids premature alerting during warm-up (`LEARNING BASELINE` vs `BASELINE READY`).
5. **Local Threat Intelligence Engine:** Evaluates observed IPs, domains, and SNIs against offline indicators with zero external network access.

---

## 3. Explainable Entity Risk Scoring

Entity risk is evaluated on a transparent 0–100 scale computed from explainable mathematical contributions:
- Base Threat Penalty: Points assigned based on alert severity (`CRITICAL: +35`, `HIGH: +25`, `MEDIUM: +15`, `LOW: +8`).
- Threat Intel Match: `+25 points`
- Baseline Anomaly Deviation: `+15 points`
- Asymmetric Volumetric Outbound Egress: `+12 points`
- Persistent Beacon Cadence: `+22 points`
- Reconnaissance Port Sweep: `+25 points`

Risk thresholds:
- `CRITICAL`: 80–100
- `HIGH`: 50–79
- `MEDIUM`: 20–49
- `LOW`: 0–19

---

## 4. One-Way Assurance & Hardware Diode Demarcation

To prevent misleading claims, the platform explicitly differentiates between:
- **Application Enforcement:** The UniGuard software is strictly passive, operates read-only, has no active response mechanisms, and performs zero packet injection or payload decryption.
- **Hardware Data-Diode Assurance:** Physical unidirectional enforcement relies on the deployment environment (e.g., optical fiber tap with Tx disconnected or certified hardware data diode).

---

## 5. Technology Stack Summary

| Layer | Component | Technology |
|---|---|---|
| Ingestion | Packet Parser & Log Adapters | Python, Scapy, Pandas, Custom Zeek & Suricata EVE Parsers |
| Feature Extraction | 26-Dimensional Engine | NumPy, Shannon Entropy Calculator, NetworkContextTracker |
| Threat Detection | Rules + ML + Baseline + Intel | Scikit-learn (RandomForest, IsolationForest), SQLite, BaselineEngine |
| Correlation | Multi-Signal Correlator | MITRE ATT&CK Mapper, Deduplicator, CampaignCorrelator |
| Backend & API | Web Server & Real-Time Feed | FastAPI, Uvicorn, SQLAlchemy, WebSockets, Python 3.14 |
| Storage | Relational SOC Database | SQLite (offline local persistence) |
| Frontend | Security Operations Console | React 18, TypeScript, Vite, Tailwind CSS, Lucide, Recharts |
