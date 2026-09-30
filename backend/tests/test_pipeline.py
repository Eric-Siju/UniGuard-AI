"""
Comprehensive Pytest Test Suite for UniGuard AI
Tests parsing, feature extraction, all 6 threat detection rules,
ML inference, anomaly scoring, threat correlation, and REST API endpoints.
"""

import pytest
import os
import io
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models.database import init_db
from backend.app.core.config import DATA_DIR
from backend.app.engine.feature_extractor import extract_flow_features, calculate_shannon_entropy
from backend.app.engine.rules import (
    RuleEngine, DDoSRule, PortScanRule, BotnetBeaconRule,
    DNSTunnelingRule, SuspiciousEncryptedRule, DataExfiltrationRule
)
from backend.app.engine.ml_detector import ml_detector
from backend.app.engine.correlator import threat_correlator
from backend.app.engine.parser import parse_csv_file, parse_pcap_file
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

# Initialize SQLite tables for tests
init_db()

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["passive_mode"] is True
    assert data["read_only_monitoring"] is True
    assert data["active_response_enabled"] is False

def test_shannon_entropy():
    norm_ent = calculate_shannon_entropy("google.com")
    assert 2.0 <= norm_ent <= 3.2
    
    dga_ent = calculate_shannon_entropy("q7w8e9r0t1y2u3i4o5p6a7s8d9f0.covert-tunnel.org")
    assert dga_ent >= 3.6
    
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy(None) == 0.0

def test_feature_extraction():
    flow = {
        "src_ip": "10.0.1.10",
        "dst_ip": "10.0.1.20",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 2.0,
        "total_bytes": 10000,
        "total_packets": 20,
        "tcp_flags": "SA"
    }
    feats = extract_flow_features(flow, update_context=False)
    assert "duration" in feats
    assert feats["total_bytes"] == 10000.0
    assert feats["total_packets"] == 20.0
    assert feats["packets_per_sec"] == 10.0
    assert feats["bytes_per_sec"] == 5000.0
    assert feats["syn_count"] == 1.0

def test_ddos_rule():
    rule = DDoSRule()
    ddos_flow = {
        "src_ip": "198.51.100.12",
        "dst_ip": "10.0.1.50",
        "src_port": 45000,
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 0.05,
        "total_bytes": 50000,
        "total_packets": 50,
        "tcp_flags": "S"
    }
    feats = {
        "packets_per_sec": 1000.0,
        "bytes_per_sec": 1000000.0,
        "syn_ratio": 0.95,
        "fan_in": 25.0,
        "total_packets": 50.0
    }
    match = rule.evaluate(ddos_flow, feats)
    assert match is not None
    assert match.threat_class == "DDoS"
    assert match.confidence >= 0.80

def test_port_scan_rule():
    rule = PortScanRule()
    scan_flow = {
        "src_ip": "192.168.1.185",
        "dst_ip": "10.0.1.5",
        "src_port": 50000,
        "dst_port": 8080,
        "protocol": "TCP",
        "duration": 0.05,
        "total_packets": 2
    }
    feats = {
        "unique_dst_ports": 45.0,
        "fan_out": 12.0,
        "duration": 0.05,
        "conn_frequency": 15.0,
        "syn_ratio": 0.90
    }
    match = rule.evaluate(scan_flow, feats)
    assert match is not None
    assert match.threat_class == "Port Scan"
    assert match.severity in ["HIGH", "CRITICAL"]

def test_botnet_normal_https_does_not_trigger():
    """Proves that normal HTTPS browsing flows (single or irregular) DO NOT trigger Botnet C2 false positives."""
    rule = BotnetBeaconRule()
    rule.reset()
    
    # 1. Single normal HTTPS flow on port 443 with small response
    normal_flow_1 = {
        "flow_id": "norm_https_1",
        "src_ip": "10.0.1.100",
        "dst_ip": "142.250.190.46",  # e.g. google.com
        "src_port": 51234,
        "dst_port": 443,
        "protocol": "TCP",
        "duration": 0.15,
        "total_bytes": 450,
        "total_packets": 4,
        "ts_epoch": 1000.0
    }
    feats_1 = {
        "total_bytes": 450.0,
        "total_packets": 4.0,
        "avg_packet_size": 112.5,
        "iat_mean": 0.05,
        "iat_std": 0.01
    }
    match_1 = rule.evaluate(normal_flow_1, feats_1)
    assert match_1 is None, "Single normal HTTPS flow must never trigger Botnet C2"

    # 2. Subsequent irregular normal web flows with human jitter and varying packet sizes
    for i, (dt, size) in enumerate([(1.2, 1200), (4.5, 34000), (0.8, 800)]):
        flow = {
            "flow_id": f"norm_https_{i+2}",
            "src_ip": "10.0.1.100",
            "dst_ip": "142.250.190.46",
            "src_port": 51234,
            "dst_port": 443,
            "protocol": "TCP",
            "duration": 0.2,
            "total_bytes": size,
            "total_packets": max(int(size / 300), 2),
            "ts_epoch": 1000.0 + dt * (i + 1)
        }
        feats = {
            "total_bytes": float(size),
            "total_packets": float(max(int(size / 300), 2)),
            "avg_packet_size": float(size / max(int(size / 300), 2)),
            "iat_mean": dt / 4.0,
            "iat_std": 0.5
        }
        match = rule.evaluate(flow, feats)
        assert match is None, f"Irregular web traffic observation {i+2} must not trigger Botnet C2"

def test_botnet_synthetic_beacon_sequence_triggers():
    """Proves that a synthetic botnet beacon sequence with periodic cadence DOES trigger Botnet C2."""
    rule = BotnetBeaconRule()
    rule.reset()
    
    c2_ip = "194.26.29.112"
    bot_ip = "10.0.1.14"
    c2_port = 8443
    base_t = 2000.0
    
    matches = []
    # Send a sequence of 5 periodic beacons every 5.0 seconds with small payload
    for i in range(5):
        # 5.0s cadence with negligible jitter (0.01s)
        t = base_t + (i * 5.0) + (0.01 if i % 2 == 0 else -0.01)
        flow = {
            "flow_id": f"c2_beacon_{i}",
            "src_ip": bot_ip,
            "dst_ip": c2_ip,
            "src_port": 49152 + i,
            "dst_port": c2_port,
            "protocol": "TCP",
            "duration": 0.2,
            "total_bytes": 220,
            "total_packets": 5,
            "ts_epoch": t
        }
        feats = {
            "total_bytes": 220.0,
            "total_packets": 5.0,
            "avg_packet_size": 44.0,
            "iat_mean": 0.05,
            "iat_std": 0.01
        }
        match = rule.evaluate(flow, feats)
        matches.append(match)
        
    # Beacons 0, 1, 2 should be None because min_beacons = 4
    assert matches[0] is None
    assert matches[1] is None
    assert matches[2] is None
    
    # Beacon 3 (4th observation) and Beacon 4 (5th observation) MUST trigger Botnet C2
    assert matches[3] is not None
    assert matches[3].threat_class == "Botnet C2"
    assert matches[3].confidence >= 0.70
    assert any("periodic heartbeat" in ev.lower() for ev in matches[3].evidence)
    assert any("persistent c2" in ev.lower() for ev in matches[3].evidence)
    
    assert matches[4] is not None
    assert matches[4].threat_class == "Botnet C2"


def test_dns_tunneling_rule():
    rule = DNSTunnelingRule()
    dns_flow = {
        "src_ip": "10.0.1.19",
        "dst_ip": "10.0.1.2",
        "dst_port": 53,
        "protocol": "DNS",
        "dns_query": "4a7b9c1d3e5f7a9b.sub.exfiltration-tunnel.com"
    }
    feats = {
        "dns_entropy": 4.1,
        "dns_query_length": 45.0,
        "dns_digit_ratio": 0.35,
        "dns_subdomain_depth": 3.0
    }
    match = rule.evaluate(dns_flow, feats)
    assert match is not None
    assert match.threat_class == "DGA / DNS Tunneling"

def test_data_exfiltration_rule():
    rule = DataExfiltrationRule()
    exfil_flow = {
        "src_ip": "10.0.1.15",
        "dst_ip": "91.215.85.17",
        "dst_port": 443,
        "protocol": "TCP"
    }
    feats = {
        "outbound_bytes": 15_000_000,
        "outbound_ratio": 45.0,
        "bytes_per_sec": 500_000,
        "duration": 30.0
    }
    match = rule.evaluate(exfil_flow, feats)
    assert match is not None
    assert match.threat_class == "Data Exfiltration"
    assert match.severity == "CRITICAL"

def test_ml_inference_and_anomaly():
    assert ml_detector.is_loaded is True
    normal_feats = {
        "duration": 1.5, "total_bytes": 1200, "total_packets": 6, "packets_per_sec": 4.0,
        "bytes_per_sec": 800.0, "avg_packet_size": 200.0, "packet_size_std": 30.0,
        "iat_mean": 0.3, "iat_std": 0.1, "iat_min": 0.05, "iat_max": 0.5,
        "fan_in": 1.0, "fan_out": 2.0, "unique_dst_ports": 1.0, "unique_src_ports": 1.0,
        "conn_frequency": 1.0, "syn_count": 1.0, "ack_count": 1.0, "rst_count": 0.0,
        "syn_ratio": 0.5, "dns_query_length": 15.0, "dns_entropy": 2.6,
        "dns_digit_ratio": 0.0, "dns_subdomain_depth": 1.0,
        "outbound_bytes": 600.0, "outbound_ratio": 1.0
    }
    res = ml_detector.predict(normal_feats)
    assert "prediction" in res
    assert "probabilities" in res
    assert "anomaly_score" in res
    assert "contributing_features" in res
    assert isinstance(res["contributing_features"], list)

def test_csv_parser():
    normal_csv = DATA_DIR / "normal.csv"
    assert normal_csv.exists()
    flows = parse_csv_file(str(normal_csv))
    assert len(flows) > 0
    f0 = flows[0]
    assert "flow_id" in f0
    assert "src_ip" in f0
    assert "dst_ip" in f0
    assert "protocol" in f0

def test_api_endpoints():
    with TestClient(app) as test_client:
        res = test_client.get("/api/stats")
        assert res.status_code == 200
        stats = res.json()
        assert "flows_processed" in stats
        assert "threats_detected" in stats
        assert stats["passive_mode"] is True

        res = test_client.get("/api/models")
        assert res.status_code == 200
        meta = res.json()
        assert "accuracy" in meta
        assert meta["accuracy"] > 0.90

        res = test_client.get("/api/threats/summary")
        assert res.status_code == 200

        res = test_client.get("/api/flows?limit=10")
        assert res.status_code == 200
        
        res = test_client.get("/api/report?format=html")
        assert res.status_code == 200
        assert "UniGuard AI" in res.text

def test_demo_scenario_whitelist():
    """Validates that only strictly whitelisted demo scenarios are accepted."""
    with TestClient(app) as test_client:
        # Whitelisted scenarios should succeed
        for sc in ["combined_demo", "ddos", "botnet", "normal"]:
            res = test_client.post("/api/demo/start", json={"scenario": sc, "speed": 1.0})
            assert res.status_code == 200
            assert res.json()["status"] == "started"
            test_client.post("/api/demo/stop")

        # Non-whitelisted scenarios or path traversal attempts MUST be rejected with HTTP 400
        for bad in ["../../etc/passwd", "hack_exploit", "arbitrary_dataset", "unknown"]:
            res = test_client.post("/api/demo/start", json={"scenario": bad, "speed": 1.0})
            assert res.status_code == 400
            assert "Invalid scenario" in res.json()["detail"]

def test_upload_security_validation():
    """Validates strict file extension checking and safe handling on file uploads."""
    with TestClient(app) as test_client:
        # Invalid extension for CSV endpoint
        fake_exe = io.BytesIO(b"MZ executable header")
        res = test_client.post("/api/upload/csv", files={"file": ("malware.exe", fake_exe, "application/octet-stream")})
        assert res.status_code == 400
        assert "Only .csv files are supported" in res.json()["detail"]

        # Valid CSV upload
        valid_csv_content = b"src_ip,dst_ip,src_port,dst_port,protocol,duration,total_bytes,total_packets,threat_label\n10.0.1.5,10.0.1.10,5000,80,TCP,0.1,500,5,Normal\n"
        res = test_client.post("/api/upload/csv", files={"file": ("../../traversal_test.csv", io.BytesIO(valid_csv_content), "text/csv")})
        assert res.status_code == 200
        assert res.json()["flows_parsed"] == 1

def test_spa_root_and_fallback():
    """Verifies that the single official React web application is served at root and SPA routes."""
    with TestClient(app) as test_client:
        res = test_client.get("/")
        assert res.status_code == 200
        assert "html" in res.headers.get("content-type", "").lower()
        # Verify it contains UniGuard React HTML shell
        assert "UniGuard AI" in res.text

        # SPA client-side route fallback
        res_spa = test_client.get("/investigation")
        assert res_spa.status_code == 200
        assert "html" in res_spa.headers.get("content-type", "").lower()

        # Non-existent API route must return 404, not SPA html
        res_api_404 = test_client.get("/api/unknown_endpoint_xyz")
        assert res_api_404.status_code == 404

def test_pcap_parser_and_upload(tmp_path):
    """Proves genuine passive PCAP ingestion, packet parsing, flow aggregation, and upload."""
    pcap_file = str(tmp_path / "test_capture.pcap")
    pkts = [
        IP(src="192.168.1.50", dst="10.0.1.10") / TCP(sport=49152, dport=80, flags="S"),
        IP(src="192.168.1.50", dst="10.0.1.10") / TCP(sport=49152, dport=80, flags="A"),
        IP(src="192.168.1.50", dst="10.0.1.2") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname="test.uniguard.local"))
    ]
    wrpcap(pcap_file, pkts)

    # 1. Direct parsing test
    flows = parse_pcap_file(pcap_file)
    assert len(flows) >= 1
    tcp_flows = [f for f in flows if f["protocol"] == "TCP"]
    assert len(tcp_flows) >= 1
    assert tcp_flows[0]["src_ip"] == "192.168.1.50"
    assert tcp_flows[0]["dst_ip"] == "10.0.1.10"
    assert tcp_flows[0]["dst_port"] == 80

    # 2. Upload API test
    with TestClient(app) as test_client:
        with open(pcap_file, "rb") as pf:
            res = test_client.post(
                "/api/upload/pcap",
                files={"file": ("test_capture.pcap", pf, "application/vnd.tcpdump.pcap")}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "success"
            assert data["flows_aggregated"] >= 1
            assert len(data["sample_flows"]) >= 1


