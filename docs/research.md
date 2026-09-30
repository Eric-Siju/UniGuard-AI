# UniGuard AI: Official NSM & Unidirectional Monitoring Research

**Problem Statement:** SIH26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Platform Architecture:** Passive, Read-Only, Unidirectional, Offline-First, Non-Offensive Network Security Operations Platform

---

## 1. Professional Network Security Monitoring (NSM) Design References

### 1.1 Zeek (formerly Bro)
* **Official Concepts:**
  - `conn.log`: Connection-level summarization (timestamps, duration, src/dst IPs, ports, protocol, service, bytes, packets, state flags).
  - `dns.log`: DNS query metadata (query name, record type, response code, round-trip time, entropy).
  - `ssl.log` & `x509.log`: TLS handshake metadata (SNI server name, TLS version, cipher suite, certificate validity) without payload decryption.
  - **Notice Framework**: Thresholding and escalating suspicious single or aggregated events into actionable analyst notices.
  - **Intelligence Framework**: Rapid indicator lookup (IP, domain, hash) without external network egress.
* **UniGuard Adaptation:**
  - UniGuard adopts Zeek's modular logging philosophy by extracting connection summaries and protocol metadata passively from IP headers and handshake records.
  - We provide a native Zeek JSON parser (`conn.log`, `dns.log`, `ssl.log`) so SOC teams can ingest existing Zeek telemetry into UniGuard's AI engine.
* **Unidirectional Relevance:**
  - In a diode environment, Zeek sensors operate on optical TAP feeds. UniGuard mirrors this by enforcing zero reverse-path traffic.

### 1.2 Suricata (IDS/IPS/NSM)
* **Official Concepts:**
  - **EVE JSON Output**: Extensible unified JSON stream emitting alerts, flow telemetry, DNS records, TLS handshakes, NetFlow stats, and anomalies.
  - **Thresholding & Rate Limiting**: Suppressing high-frequency identical alerts (`event_filter`, `threshold`) to prevent analyst fatigue.
  - **Flow Tracking**: In-memory state tracking to calculate bidirectional metrics (bytes sent, flags) from stream fragments.
* **UniGuard Adaptation:**
  - UniGuard ingests Suricata EVE JSON (`alert`, `flow`, `dns`, `tls`, `anomaly`) and normalizes external alerts alongside our internal multi-signal ML detections.
  - Implements alert deduplication and time-windowed suppression inspired by Suricata thresholding.
* **Unidirectional Relevance:**
  - Standard Suricata rule matching often assumes bidirectional TCP handshakes (SYN, SYN-ACK, ACK). In unidirectional tapping, return traffic may be absent; UniGuard detects threats using asymmetric half-flow features and timing heuristics.

### 1.3 Security Onion
* **Official Concepts:**
  - **Alerts, Hunt, Cases, Dashboards**: Segregation of analyst workflows from triage (Alerts) to proactive hypothesis testing (Hunt) and formal escalation (Cases).
  - **Cases Management**: Centralizing evidence, notes, affected assets, and timeline artifacts into a formal case dossier.
* **UniGuard Adaptation:**
  - Implements a streamlined Case Management system allowing one-click escalation from alerts into SOC cases with analyst notes and status tracking.
  - Implements a dedicated Threat Hunt interface with structured pivoting (Flow → Asset → Alert → Case).
* **Unidirectional Relevance:**
  - SOC analysts cannot active-probe or ping suspect hosts to verify; all investigation must rely strictly on passively captured historical telemetry.

### 1.4 Elastic Security
* **Official Concepts:**
  - **Entity Risk Scoring**: Continual scoring (0–100) of hosts and users based on alert density, severity multipliers, and behavioral deviations.
  - **Alert Suppression & Deduplication**: Grouping related alerts by entity and rule to present single grouped incidents.
  - **Timeline Investigation**: Reconstructing multi-stage attack actions across time.
* **UniGuard Adaptation:**
  - UniGuard introduces transparent Entity Risk Scoring with explicit mathematical factor breakdowns (`+25 Port Scan`, `+18 C2 Beaconing`, etc.).
  - Alerts are grouped by source IP and threat class with occurrence counters.
* **Unidirectional Relevance:**
  - Without endpoint agents (which require bidirectional communication), entity risk must be deduced entirely from passive ingress traffic attributes.

### 1.5 NIST SP 800-82 / NCCoE (Data Diodes & Unidirectional Gateways)
* **Official Concepts:**
  - Hardware data diodes enforce physical unidirectional communication (e.g., fiber TX only, disconnected RX).
  - Situational awareness in OT/ICS/SCADA requires observing egress or ingress data streams without introducing ingress network paths into protected enclaves.
* **UniGuard Adaptation:**
  - Dedicated **One-Way Assurance Monitor**: Explicitly displays physical TAP/diode architecture vs. application-layer passive enforcement.
  - Assures zero transmission, no active scanning, no RST injection, and no remote C2 callback.

### 1.6 MITRE ATT&CK for Enterprise
* **Mapped Techniques:**
  - **T1046 Network Service Discovery**: Rapid port probing, SYN-dominant half-flows.
  - **T1071 Application Layer Protocol**: C2 communications leveraging common ports (HTTP, HTTPS).
  - **T1071.004 DNS**: DGA (Domain Generation Algorithms) and DNS Tunneling for exfiltration/C2.
  - **T1498 / T1499 Network/Endpoint Denial of Service**: High-rate SYN/UDP flood saturation.
  - **T1573 Encrypted Channel**: Suspicious SSL/TLS handshakes, self-signed or anomalous SNI.
  - **T1041 Exfiltration Over C2 Channel**: High-volume asymmetric outbound transfer without reciprocal traffic.
* **UniGuard Adaptation:**
  - Alerts display MITRE technique ID, technique name, and tactical category directly in the analyst card.

---

## 2. Research Takeaways for UniGuard Engineering

| NSM Domain | Reference Standard | UniGuard Implementation Strategy |
| :--- | :--- | :--- |
| **Ingestion** | Zeek & Suricata JSON | Unified multi-source adapter (`/api/upload/zeek`, `/api/upload/eve`, `/api/datasources`) |
| **Detection** | Multi-Signal Consensus | 5-way consensus: Rules + Supervised ML + Anomaly + Local Intel + Baseline |
| **Alerting** | Suricata Thresholding | Time-windowed alert deduplication and occurrence grouping |
| **Scoring** | Elastic Entity Analytics | Explainable Entity Risk (0–100) with contributory factors |
| **Investigation** | Security Onion Cases | Native SOC Cases (`/api/cases`) and Threat Hunting (`/api/hunt`) |
| **Assurance** | NIST SP 800-82 | Passive One-Way Assurance visual console & operational health telemetry |
