"""
Unit & Integration Tests for UniGuard AI Enhanced NSM / SOC Capabilities
Smart India Hackathon SIH26145 - Unidirectional Passive Cyber Defense
"""

import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.database import SessionLocal, Alert, FlowRecord, Case, ThreatIntelIndicator
from backend.app.engine.ingestion.zeek import ZeekJsonAdapter
from backend.app.engine.ingestion.suricata import SuricataEveAdapter
from backend.app.engine.threat_intel import threat_intel
from backend.app.engine.baseline import baseline_engine
from backend.app.engine.dedup import deduplicator
from backend.app.engine.entity_risk import compute_entity_risk, get_asset_inventory
from backend.app.engine.campaign import campaign_correlator
from backend.app.engine.case_manager import case_manager
from backend.app.engine.correlator import threat_correlator

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()

def test_zeek_json_ingestion():
    adapter = ZeekJsonAdapter()
    sample_zeek = (
        '{"ts": 1690000001.0, "uid": "CZ1", "id.orig_h": "192.168.1.100", "id.orig_p": 50123, "id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp", "duration": 0.25, "orig_bytes": 1500, "resp_bytes": 0, "orig_pkts": 8, "conn_state": "S0"}\n'
        '{"ts": 1690000002.0, "uid": "CZ2", "id.orig_h": "192.168.1.101", "id.orig_p": 53120, "id.resp_h": "10.0.0.2", "id.resp_p": 53, "proto": "udp", "query": "exfil-tunnel.test", "duration": 0.05, "orig_bytes": 120, "resp_bytes": 0, "orig_pkts": 1}\n'
    )
    flows = adapter.parse_content(sample_zeek)
    assert len(flows) == 2
    assert flows[0]["src_ip"] == "192.168.1.100"
    assert flows[0]["dst_port"] == 443
    assert flows[0]["is_encrypted"] is True
    assert flows[1]["dns_query"] == "exfil-tunnel.test"

def test_suricata_eve_ingestion():
    adapter = SuricataEveAdapter()
    sample_eve = (
        '{"timestamp": "2026-09-30T10:00:00.000Z", "event_type": "flow", "src_ip": "10.0.0.5", "src_port": 49152, "dest_ip": "10.0.0.99", "dest_port": 8080, "proto": "TCP", "flow": {"bytes_toserver": 1200, "bytes_toclient": 0, "pkts_toserver": 6, "pkts_toclient": 0, "age": 0.8}}\n'
        '{"timestamp": "2026-09-30T10:00:01.000Z", "event_type": "dns", "src_ip": "10.0.0.5", "src_port": 5353, "dest_ip": "10.0.0.2", "dest_port": 53, "proto": "UDP", "dns": {"rrname": "suspicious-dga-longdomain.internal"}}\n'
    )
    flows = adapter.parse_content(sample_eve)
    assert len(flows) == 2
    assert flows[0]["src_ip"] == "10.0.0.5"
    assert flows[0]["dst_ip"] == "10.0.0.99"
    assert flows[1]["protocol"] == "DNS"
    assert flows[1]["dns_query"] == "suspicious-dga-longdomain.internal"

def test_local_threat_intel_matching():
    # Test pre-seeded indicator match
    flow = {
        "src_ip": "192.168.1.20",
        "dst_ip": "10.0.0.99",
        "dns_query": None,
        "sni": None
    }
    match = threat_intel.check_flow(flow)
    assert match is not None
    assert match.matched is True
    assert match.indicator == "10.0.0.99"
    assert "C2" in match.description

    # Test benign IP (no match)
    benign_flow = {
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.5",
        "dns_query": "google.com",
        "sni": "google.com"
    }
    benign_match = threat_intel.check_flow(benign_flow)
    assert benign_match is None

def test_mitre_mapping_in_correlator():
    flow = {
        "flow_id": "test_mitre_1",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "total_bytes": 100,
        "total_packets": 2,
        "duration": 0.05
    }
    features = {
        "packets_per_sec": 10.0,
        "bytes_per_sec": 500.0,
        "unique_dst_ports": 25.0,
        "fan_out": 15.0,
        "duration": 0.05
    }
    ml_result = {"prediction": "Port Scan", "confidence": 0.92, "anomaly_score": 0.1, "is_anomaly": False}
    alert = threat_correlator.correlate(flow, features, [], ml_result)
    assert alert is not None
    assert alert.threat_type == "Port Scan"
    assert alert.mitre_technique_id == "T1046"
    assert alert.mitre_technique_name == "Network Service Discovery"
    assert alert.mitre_tactic == "Discovery"

def test_alert_deduplication():
    raw_alert = {
        "alert_id": "ALT-TEST-DEDUP-1",
        "threat_type": "Port Scan",
        "severity": "HIGH",
        "confidence": 0.90,
        "risk_score": 75.0,
        "src_ip": "192.168.5.5",
        "dst_ip": "10.0.0.50",
        "dst_port": 80,
        "protocol": "TCP",
        "evidence": ["High port sweep: 18 ports"]
    }
    # First time -> new alert
    res1, is_new1 = deduplicator.process(raw_alert)
    assert is_new1 is True
    assert res1["occurrences"] == 1
    assert res1["suppressed_count"] == 0

    # Second time within window -> suppressed duplicate
    raw_alert2 = dict(raw_alert)
    raw_alert2["alert_id"] = "ALT-TEST-DEDUP-2"
    raw_alert2["dst_port"] = 81
    res2, is_new2 = deduplicator.process(raw_alert2)
    assert is_new2 is False
    assert res2["alert_id"] == "ALT-TEST-DEDUP-1"  # Keeps original primary ID
    assert res2["occurrences"] == 2
    assert res2["suppressed_count"] == 1

def test_entity_risk_scoring():
    alerts = [
        Alert(alert_id="a1", threat_type="Port Scan", severity="HIGH", confidence=0.9),
        Alert(alert_id="a2", threat_type="Botnet C2", severity="CRITICAL", confidence=0.95),
    ]
    risk_info = compute_entity_risk(
        ip="192.168.1.99",
        alerts=alerts,
        threat_intel_match=True,
        baseline_anomaly=True,
        high_outbound=True
    )
    assert risk_info["risk_score"] >= 80.0
    assert risk_info["risk_level"] == "CRITICAL"
    # Verify transparent contributory factors
    factors = risk_info["risk_factors"]
    factor_names = [f["factor"] for f in factors]
    assert any("Port Scan" in fn for fn in factor_names)
    assert any("Threat Intelligence" in fn for fn in factor_names)
    assert any("Baseline Volume" in fn for fn in factor_names)

def test_case_management(db):
    new_case = case_manager.create_case(
        db=db,
        title="Test Incident Investigation",
        description="Testing SOC case escalation",
        severity="HIGH",
        related_alerts=["ALT-1001", "ALT-1002"],
        related_assets=["10.0.0.55"],
        tags=["SIH26145", "Test"],
        initial_note="Case opened by automated security test"
    )
    assert new_case.case_id.startswith("CASE-")
    assert new_case.status == "OPEN"
    assert len(new_case.analyst_notes) == 1

    # Update case
    updated = case_manager.update_case(
        db=db,
        case_id=new_case.case_id,
        new_note="Added evidence from passive TAP",
        status="INVESTIGATING"
    )
    assert updated.status == "INVESTIGATING"
    assert len(updated.analyst_notes) == 2

def test_api_endpoints(client):
    # Stats endpoint
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    assert "flows_processed" in stats_res.json()

    # Data sources endpoint
    ds_res = client.get("/api/datasources")
    assert ds_res.status_code == 200
    data = ds_res.json()
    assert "sources" in data
    assert len(data["sources"]) >= 5

    # One-Way Assurance endpoint
    assur_res = client.get("/api/assurance")
    assert assur_res.status_code == 200
    assur_data = assur_res.json()
    assert assur_data["guarantees"]["application_enforcement"] == "PASSIVE_READ_ONLY"
    assert assur_data["guarantees"]["active_response"] is False

    # Threat Intel endpoint
    intel_res = client.get("/api/threat-intel")
    assert intel_res.status_code == 200
    assert len(intel_res.json()["indicators"]) >= 5

    # Assets endpoint
    assets_res = client.get("/api/assets")
    assert assets_res.status_code == 200
    assert "assets" in assets_res.json()

    # Campaigns endpoint
    camp_res = client.get("/api/campaigns")
    assert camp_res.status_code == 200
    assert "campaigns" in camp_res.json()

    # Threat hunt endpoint
    hunt_res = client.get("/api/hunt?limit=10")
    assert hunt_res.status_code == 200
    assert "items" in hunt_res.json()
