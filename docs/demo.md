# SIH Judge Demonstration Walkthrough (`docs/demo.md`)

This guide provides the official presentation script and walkthrough for demonstrating **UniGuard AI** to the evaluators for Smart India Hackathon 2026 problem statement **SIH26145**.

---

## Quick Launch
```powershell
# In Windows PowerShell:
.\.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in Google Chrome.

---

## Presentation Method 1: The Guided 12-Step "Judge Mode" (Recommended)

Click the gold **JUDGE MODE** button in the top header. This opens a modal that guides the panel through the complete defense narrative step-by-step:

| Step | Title | Target Tab | What It Demonstrates |
|---|---|---|---|
| **1** | Architecture Verification | `compliance` | Shows one-way optical tap architecture and four compliance badges (`PASSIVE`, `READ-ONLY`, `NO ACTIVE RESPONSE`, `NO PAYLOAD DECRYPTION`). |
| **2** | Normal Traffic Baseline | `dashboard` | Runs normal baseline flows. Shows behavioral engine in `LEARNING BASELINE` state without raising false alarms. |
| **3** | Phase 1: Port Scan Reconnaissance | `dashboard` | Triggers synthetic reconnaissance sweep. Alert generated with MITRE T1046 mapping and deduplication. |
| **4** | Phase 2: Botnet C2 Beaconing | `investigation` | Triggers periodic heartbeat beacons. Proves strict IAT jitter calculation distinguishes beacons from normal HTTPS. |
| **5** | Phase 3: DGA & DNS Tunneling | `investigation` | Triggers high-entropy domain lookups. Shows Shannon entropy (>3.5 bits) and query length features. |
| **6** | Phase 4: Data Exfiltration | `investigation` | Triggers asymmetric outbound egress. Flags extreme outbound-to-inbound byte ratios. |
| **7** | Multi-Signal Consensus & XAI | `investigation` | Shows the 5-way pipeline (Rule + ML + Anomaly + Baseline + Intel) with exact plain-language reasoning. |
| **8** | Passive Asset Inventory & Entity Risk | `assets` | Displays assets inferred from traffic. Shows explainable 0–100 risk score with mathematical factor breakdown. |
| **9** | Multi-Stage Campaign Correlation | `campaigns` | Demonstrates how 4 separate alerts against one entity are correlated into an intrusion campaign story. |
| **10** | SOC Case Management & Dossier | `cases` | Escalates an alert to a formal Case. Adds analyst notes, sets status to `INVESTIGATING`, and exports a `.txt` dossier. |
| **11** | Passive Threat Hunting Console | `hunt` | Demonstrates analyst queries by IP, port, protocol, and severity with one-click pivots. |
| **12** | Model Lab & Hardware Benchmark | `benchmark` | Executes real on-hardware timing benchmark (e.g. 0.015ms feature extraction, 13+ flows/sec). |

---

## Presentation Method 2: Manual Feature-by-Feature Walkthrough

### 1. Header & One-Way Assurance
- Point out the 4 mandatory passive badges in the header.
- Navigate to the **One-Way Diode** tab to review the architecture diagram and telemetry health counters.

### 2. Ingestion & Interoperability
- Navigate to **Data Sources**.
- Demonstrate the ready state of all 6 NSM ingestion adapters (Demo Stream, CSV Upload, PCAP Parser, Zeek JSON Adapter, Suricata EVE Adapter, Threat Intel).
- Show that sample Zeek logs or Suricata EVE logs can be uploaded and normalized locally without requiring third-party enterprise clusters.

### 3. Live Streaming & Deduplication
- Start the `Combined Attack Wave` at `2x` or `5x` speed.
- Observe live alerts appearing in the feed. Point out that repeated identical events are grouped (e.g. `Occurrences: 12`, `Suppressed: 11`) rather than flooding the analyst's screen.

### 4. Alert Triage & Explainable AI
- Click **Investigate** on an alert.
- Review the **Detection Pipeline**:
  - Rule Engine: `MATCH`
  - Random Forest: `98.0%`
  - Anomaly Detector: `HIGH`
  - Threat Intel: `MATCH` or `NONE`
  - Baseline Deviation: `+1005%`
- Review the plain-English explanation: *"Observed 45 unique destination ports, connection frequency 15.0/s exceeded baseline by 8.4x"*.

### 5. Case Management
- Click **Escalate to Case** from the investigation view.
- Give the case a title (e.g. *"APT-Reconnaissance Incident #26145"*).
- Add an analyst note and export the formal investigation dossier.

### 6. Threat Hunting
- Navigate to **Threat Hunt**.
- Filter by `Protocol: TCP` and `Severity: HIGH`.
- Pivot to any source IP to instantly view all historical communications and asset profile.

### 7. Performance & Reporting
- Navigate to **Benchmark** and click **Run Live Hardware Benchmark**. Explain that numbers are measured on the physical machine, never fabricated.
- Navigate to **Reports** and print or export the PDF executive summary.
