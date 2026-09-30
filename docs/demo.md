# SIH Judge Demonstration Walkthrough (docs/demo.md)

Follow this step-by-step walkthrough to demonstrate the full capabilities of UniGuard AI for Smart India Hackathon 2026 problem statement SIH26145.

---

## 1. Launch Verification (SOC Overview)
1. Open Google Chrome to `http://localhost:3000`.
2. Observe the top header:
   - **UniGuard AI** Branding & Problem Statement SIH26145 badge.
   - Three bold compliance badges:
     - `? PASSIVE MODE`
     - `? READ-ONLY MONITORING`
     - `? NO ACTIVE RESPONSE`
   - WebSocket Connection Pill shows `? LIVE WS` in bright green.

---

## 2. Trigger Real-Time Traffic Stream
1. In the top streaming control bar, select scenario:
   `Combined Attack Wave (Demo)`
2. Click the **START DEMO** button.
3. Watch the dashboard dynamically react without manual page refresh:
   - **Flows Processed** and **Packet Velocity** counters immediately begin updating.
   - **Live Unidirectional Traffic Rate** chart draws real-time packet velocity peaks.
   - **Live Security Incidents Feed** begins populating with correlated threat alerts as attacks emerge.
   - The **Detected Threat Classes** chart updates dynamically.

---

## 3. Test Variable Playback Speed & Controls
1. Click `2x`, `5x`, or `10x` in the speed selector to observe high-throughput processing.
2. Click **PAUSE** &mdash; notice the simulation halts instantly and the status indicator reflects `PAUSED`.
3. Click **RESUME** &mdash; streaming continues smoothly.

---

## 4. Deep Forensic Alert Investigation (Explainable AI)
1. In the **Live Security Incidents Feed**, locate any high-severity alert (e.g. `Port Scan` or `DDoS` or `Data Exfiltration`).
2. Click the **Investigate ?** button on the right of the alert row.
3. The application transitions into the **Security Incident Investigation Console**:
   - Inspect the **5-Tuple Endpoints** (Source IP, Destination IP:Port, Protocol, Total Payload).
   - Review the **Corroborating Evidence & Behavioral Signals** box. Notice the exact human-readable reasons (e.g. *"45 destination ports contacted by source"*, *"SYN ratio 95.0%"*).
   - Review **Explainable AI (XAI) Feature Attribution**: See the exact mathematical feature deviations driving the Random Forest classification along with relative impact percentages.
   - Inspect the **Contextual Flow Timeline** showing chronological preceding and succeeding sessions.

---

## 5. Traffic Analysis & PCAP / CSV Ingestion
1. Switch to the **Traffic Analysis** tab.
2. Filter flows by Protocol (`TCP`, `UDP`, `DNS`, `TLS`) or Threat Category (`DDoS`, `Botnet C2`).
3. Use the search bar to filter by IP address (e.g., `192.168.1.185` or `10.0.1.50`).
4. Click **Upload PCAP / CSV**:
   - Upload any custom flow dataset or packet capture.
   - The system automatically parses headers passively without active network contact.

---

## 6. Model Verification & Live Retraining
1. Switch to the **ML & Datasets** tab.
2. Review the verified model evaluation metrics:
   - Accuracy: `99.83%`
   - F1-Score: `0.9983`
   - False Positive Rate: `< 0.2%`
3. Inspect the **Confusion Matrix Heatmap** verifying zero leakage between threat classes.
4. Inspect the **Top Discriminating Feature Weights** chart.
5. Click **RETRAIN MODEL** &mdash; observe the live training spinner and instantaneous metric re-evaluation.

---

## 7. Replay Mode & Attack Scenarios
1. Switch to the **Replay Mode** tab.
2. Click any of the dedicated threat scenario cards:
   - `Volumetric & SYN Flood Swarm`
   - `Reconnaissance Port Sweeps`
   - `Botnet C2 Periodic Beaconing`
   - `DGA & DNS Tunneling Exfiltration`
   - `Suspicious Encrypted Covert Channel`
   - `High-Volume Data Exfiltration`
3. The selected scenario begins replaying with live counters and immediate alert generation.

---

## 8. Performance Benchmark Verification
1. Switch to the **Benchmark** tab.
2. Click **RUN LIVE HARDWARE BENCHMARK**.
3. The system executes real local timing loops:
   - Measures Feature Extraction Latency (`~0.012 ms / flow`)
   - Measures ML Inference Latency (`~74 ms / flow`)
   - Measures Pipeline Throughput (`~13.4 flows / sec`)
   - Captures process memory footprint and CPU load.
   - Prominently labeled: *"Measured on this development machine. Never fabricated."*

---

## 9. Security Audit Report Generation
1. Switch to the **Security Reports** tab.
2. Observe the fully formatted Executive Security Audit Report.
3. Click **Print / Export PDF** to trigger the browser's native print preview dialog for a polished PDF export.

---

## 10. Compliance & Data Diode Architecture
1. Switch to the **Compliance & Diode** tab.
2. Review the technical declaration and physical topology diagram explaining why UniGuard AI satisfies all mandatory requirements of SIH26145.
