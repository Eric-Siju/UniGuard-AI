# UniGuard AI REST & WebSocket API Reference (docs/API.md)

UniGuard AI exposes a comprehensive, RESTful API along with a real-time WebSocket streaming channel.

Base URL: `http://127.0.0.1:8000`
Swagger Interactive Docs: `http://127.0.0.1:8000/docs`

---

## 1. System Health & Passive Verification

### `GET /health`
Validates backend operational state and strictly passive monitoring status.
**Response (200 OK):**
```json
{
  "status": "healthy",
  "app_name": "UniGuard AI",
  "version": "1.0.0",
  "passive_mode": true,
  "read_only_monitoring": true,
  "active_response_enabled": false,
  "timestamp": "2026-09-30T02:30:00Z"
}
```

---

## 2. Telemetry & Analytics Endpoints

### `GET /api/stats`
Returns live processing statistics, threat counters, system velocity, and host resource utilization.
**Response (200 OK):**
```json
{
  "flows_processed": 1420,
  "packets_processed": 18450,
  "threats_detected": 84,
  "suspicious_flows": 12,
  "current_risk_level": "HIGH",
  "processing_latency_ms": 11.4,
  "packets_per_sec": 240.0,
  "flows_per_sec": 16.0,
  "cpu_percent": 3.2,
  "memory_mb": 162.4,
  "passive_mode": true,
  "read_only_status": true,
  "active_response": false
}
```

### `GET /api/threats/summary`
Returns aggregate statistics grouped by threat category and severity.

---

## 3. Alerts & Investigation Endpoints

### `GET /api/alerts`
Returns paginated list of security alerts.
**Query Parameters:**
- `threat_type`: string (Optional, filter by category)
- `severity`: string (Optional: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `limit`: integer (Default: 50, Max: 500)
- `offset`: integer (Default: 0)

### `GET /api/alerts/{alert_id}`
Returns complete forensic dossier for an individual alert, including:
- 5-tuple flow endpoints
- Multi-signal rule matches
- Explainable AI feature attribution list
- Contextual traffic timeline of nearby flows from the same IP endpoints

---

## 4. Flow Inspection Endpoints

### `GET /api/flows`
Returns filterable network flow records.
**Query Parameters:**
- `threat_label`: string (Optional: `All`, `Normal`, `DDoS`, `Port Scan`, etc.)
- `protocol`: string (Optional: `All`, `TCP`, `UDP`, `DNS`, `TLS`, `ICMP`)
- `search`: string (Optional search by IP, port, or Flow ID)
- `limit`: integer (Default: 50)
- `offset`: integer (Default: 0)

---

## 5. Machine Learning & Training Endpoints

### `GET /api/models`
Returns model metadata, active estimators, training dataset, and feature importance rankings.

### `GET /api/model/evaluation`
Returns detailed holdout evaluation metrics including confusion matrix and precision/recall reports.

### `POST /api/model/train`
Triggers an end-to-end model retrain on the local dataset. Returns updated accuracy and evaluation report.

---

## 6. Simulation & Replay Controls

### `POST /api/demo/start`
Starts real-time streaming demonstration.
**Request Body:**
```json
{
  "scenario": "combined_demo",
  "speed": 1.0
}
```

### `POST /api/demo/pause`
Pauses the streaming pipeline.

### `POST /api/demo/resume`
Resumes the streaming pipeline.

### `POST /api/demo/stop`
Terminates active streaming worker.

### `GET /api/demo/status`
Returns current stream state (`RUNNING`, `PAUSED`, `STOPPED`), speed, and counters.

---

## 7. Benchmarks & Audit Reports

### `GET /api/benchmark`
Executes real local hardware performance measurement and returns feature extraction latency, inference latency, throughput, and memory footprint.

### `GET /api/report?format=html`
Renders an executive, audit-ready HTML report with embedded print CSS for direct PDF export.

---

## 8. WebSocket Stream

### `WS /ws/alerts`
Bidirectional WebSocket connection broadcasting:
- `type: "flow_event"`: Emitted on every processed flow
- `type: "threat_alert"`: Emitted whenever a correlated threat alert is generated
- `type: "stats_update"`: Emitted periodically with updated throughput & risk metrics
