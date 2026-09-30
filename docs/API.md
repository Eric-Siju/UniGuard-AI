# UniGuard AI REST & WebSocket API Reference (`docs/API.md`)

UniGuard AI exposes a comprehensive, strictly passive, offline-first RESTful API along with a real-time WebSocket telemetry channel.

**Base URL:** `http://127.0.0.1:8000`  
**Swagger Interactive Docs:** `http://127.0.0.1:8000/docs`  
**ReDoc Reference:** `http://127.0.0.1:8000/redoc`

---

## 1. System Health & One-Way Assurance

### `GET /health`
Validates backend operational state and strictly passive monitoring status.
```json
{
  "status": "healthy",
  "app_name": "UniGuard AI",
  "version": "1.0.0",
  "passive_mode": true,
  "read_only_monitoring": true,
  "active_response_enabled": false,
  "timestamp": "2026-09-30T16:35:00Z"
}
```

### `GET /api/assurance`
Returns architectural demarcation distinguishing software passive guarantees from physical hardware data diode deployment.
```json
{
  "architecture": {
    "source_enclave": "PROTECTED OPERATIONAL NETWORK (OT/ICS)",
    "tap_point": "ONE-WAY OPTICAL TAP / DATA DIODE",
    "ingestion_layer": "UNIGUARD AI PASSIVE INGESTION SENSOR",
    "analysis_layer": "ISOLATED SOC DETECTION ENGINE"
  },
  "guarantees": {
    "application_enforcement": "PASSIVE_READ_ONLY",
    "active_response": false,
    "packet_injection_permitted": false,
    "remote_command_execution": false,
    "payload_decryption": false,
    "hardware_diode_note": "Application guarantees zero reverse transmission; physical enforcement depends on optical diode deployment."
  },
  "telemetry": {
    "events_received": 1420,
    "flows_processed": 1420,
    "parsing_errors": 0,
    "processing_latency_ms": 12.5,
    "websocket_active_clients": 1,
    "ml_model_loaded": true,
    "threats_correlated": 84,
    "last_event_time": "2026-09-30T16:35:00Z"
  }
}
```

---

## 2. Telemetry & Overview Counters

### `GET /api/stats`
Returns live processing statistics, threat counters, system velocity, and host resource utilization.

### `GET /api/threats/summary`
Returns aggregate statistics grouped by threat category and severity.

---

## 3. Alerts & Lifecycle Management

### `GET /api/alerts`
Returns paginated list of security alerts with filtering by `threat_type`, `severity`, `limit`, `offset`.

### `GET /api/alerts/{alert_id}`
Returns complete forensic dossier for an individual alert (5-tuple endpoints, MITRE ATT&CK mapping, rule evidence, XAI feature attribution, deduplication count, and related flows).

### `PATCH /api/alerts/{alert_id}`
Updates alert analyst lifecycle state.
**Request Body:**
```json
{
  "status": "INVESTIGATING",
  "analyst_note": "Correlated with external reconnaissance sweep.",
  "tags": ["APT", "SIH26145"]
}
```

### `POST /api/alerts/{alert_id}/acknowledge`
Quick shortcut transitioning alert status from `NEW` to `ACKNOWLEDGED`.

---

## 4. SOC Case Management

### `GET /api/cases`
Lists all investigative incident cases.

### `POST /api/cases`
Creates a new forensic investigation case.
**Request Body:**
```json
{
  "title": "Incident #26145-A: External C2 Reconnaissance",
  "description": "Multi-stage reconnaissance activity detected against monitored subnet.",
  "severity": "HIGH",
  "analyst_notes": "Initial triage confirmed suspicious port sweep behavior.",
  "tags": ["SIH26145", "RECON", "UNIDIRECTIONAL"],
  "related_asset_ips": ["10.0.0.44", "10.0.0.88"],
  "related_alerts": ["ALT-001", "ALT-002"]
}
```

### `GET /api/cases/{case_id}`
Retrieves complete case dossier including attached alerts, chronological activity timeline, and analyst notes.

### `PATCH /api/cases/{case_id}`
Updates case status (`NEW`, `INVESTIGATING`, `RESOLVED`, `CLOSED`), adds investigation notes, or attaches/removes alerts.

### `GET /api/cases/{case_id}/export`
Exports a clean, structured plaintext incident investigation report (`.txt`) for reporting or compliance archives.

---

## 5. Passive Threat Hunting

### `POST /api/hunt`
Executes safe, parameterized queries across passively captured network flows and enriched metadata without executing arbitrary code.
**Request Body:**
```json
{
  "src_ip": "10.0.1.10",
  "dst_ip": null,
  "protocol": "TCP",
  "threat_type": null,
  "severity": "HIGH",
  "is_encrypted": null,
  "limit": 50,
  "offset": 0
}
```

---

## 6. Passive Asset Inventory & Entity Risk

### `GET /api/assets`
Returns asset inventory inferred purely from passively observed traffic. Each asset contains:
- `ip`: IP address
- `role`: Inferred role heuristic (`SERVER`, `CLIENT`, `DNS`, `GATEWAY`, `SUSPICIOUS`)
- `risk_score`: Mathematical 0–100 composite risk score
- `risk_level`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `risk_factors`: Transparent breakdown of contributors (e.g. `+25 Port Scan`, `+22 C2 Beaconing`)
- `bytes_out`, `flows_count`, `unique_ports`, `destinations_count`

### `GET /api/assets/{ip}`
Returns detailed profile for a specific asset including communication peer map, recent flows, and attached alerts.

---

## 7. Attack Campaign Correlation

### `GET /api/campaigns`
Correlates individual multi-phase alerts from the same entity over time into consolidated attack campaigns:
- Phase 1: Reconnaissance (Port Scan)
- Phase 2: Command & Control (Botnet C2, Suspicious Encrypted)
- Phase 3: Protocol Concealment / DNS Manipulation (DGA / DNS Tunneling)
- Phase 4: Data Exfiltration (Outbound bulk egress)
- Phase 5: Denial of Service (DDoS Floods)

---

## 8. Local Threat Intelligence (Offline)

### `GET /api/threat-intel`
Lists local threat indicators with zero external network egress.
```json
{
  "total": 7,
  "indicators": [ ... ],
  "mode": "OFFLINE_LOCAL_STORE",
  "egress_allowed": false
}
```

### `POST /api/threat-intel`
Adds a local offline threat indicator.
**Request Body:**
```json
{
  "indicator_type": "IP",
  "indicator": "198.51.100.99",
  "description": "Known C2 Command Node",
  "source": "Local CERT Research Feed",
  "severity": "CRITICAL"
}
```

---

## 9. Data Sources & NSM Log Ingestion

### `GET /api/datasources`
Returns operational health, parsing rates, and record counters for all 6 supported NSM adapters:
1. `Demo Stream Pipeline`
2. `CSV Upload Adapter`
3. `PCAP Passive Parser`
4. `Zeek JSON Adapter`
5. `Suricata EVE JSON Adapter`
6. `Local Threat Intel`

### `POST /api/upload/zeek`
Uploads and normalizes Zeek JSON logs (`conn.log`, `dns.log`, `ssl.log`).

### `POST /api/upload/eve`
Uploads and normalizes Suricata EVE JSON logs (`alert`, `flow`, `dns`, `tls`).

### `POST /api/upload/pcap`
Uploads and parses standard `.pcap` or `.pcapng` packet captures using Scapy.

### `POST /api/upload/csv`
Uploads and validates standard network flow CSV files.

---

## 10. Real-Time WebSocket Streaming

### `WebSocket /ws/alerts`
Live bidirectional control and unidirectional broadcast channel for flow telemetry, alerts, and system stats.
- `flow_event`: Emitted for every processed flow with optional embedded alert object.
- `stats_update`: Emitted every 1 second with real-time PPS, FPS, and resource utilization.
- `init_status`: Handshake message sent on client connect.
