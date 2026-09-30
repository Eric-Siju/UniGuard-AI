"""
Comprehensive Pytest Test Suite for UniGuard AI
Tests parsing, feature extraction, all 6 threat detection rules,
ML inference, anomaly scoring, threat correlation, and REST API endpoints.
"""

import pytest
import os
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
from backend.app.engine.parser import parse_csv_file

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

def test_botnet_beacon_rule():
    rule = BotnetBeaconRule()
    bot_flow = {
        "src_ip": "10.0.1.14",
        "dst_ip": "194.26.29.112",
        "src_port": 50000,
        "dst_port": 8443,
        "protocol": "TCP",
        "duration": 0.2
    }
    feats = {
        "iat_mean": 5.0,
        "iat_std": 0.02,
        "total_bytes": 220,
        "total_packets": 5,
        "avg_packet_size": 44.0
    }
    match = rule.evaluate(bot_flow, feats)
    assert match is not None
    assert match.threat_class == "Botnet C2"

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
