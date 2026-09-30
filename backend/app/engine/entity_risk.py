"""
Entity Risk Scoring & Asset Inventory Engine for UniGuard AI
Derived strictly from passively observed network traffic without active probing.
Implements transparent 0-100 risk scoring with fully explainable contributory factors.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.models.database import FlowRecord, Alert, ThreatIntelIndicator

def infer_asset_role(ip: str, dst_ports: List[int], threat_count: int, bytes_out: int, bytes_in: int) -> str:
    """Heuristic role classification inferred purely from passive traffic patterns."""
    if threat_count >= 3:
        return "SUSPICIOUS"
    
    # Common server ports
    server_ports = {80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 27017}
    dns_ports = {53, 853}
    
    # If the IP is known default gateway pattern
    if ip.endswith(".1") or ip.endswith(".254"):
        return "GATEWAY"
    
    if any(p in dns_ports for p in dst_ports):
        return "DNS"
        
    if any(p in server_ports for p in dst_ports) and (bytes_in > bytes_out):
        return "SERVER"
        
    if bytes_out > bytes_in:
        return "CLIENT"
        
    return "UNKNOWN"

def compute_entity_risk(
    ip: str,
    alerts: List[Alert],
    threat_intel_match: bool = False,
    baseline_anomaly: bool = False,
    high_outbound: bool = False
) -> Dict[str, Any]:
    """
    Computes an explainable Entity Risk Score from 0 to 100 with distinct contributory factors.
    """
    factors: List[Dict[str, Any]] = []
    total_score = 0.0

    # Contributor 1: Alert Severity & Frequency Breakdown
    threat_types_seen = set()
    critical_count = 0
    high_count = 0
    
    for a in alerts:
        threat_types_seen.add(a.threat_type)
        if a.severity == "CRITICAL":
            critical_count += 1
        elif a.severity == "HIGH":
            high_count += 1

    if "Port Scan" in threat_types_seen:
        points = 25.0
        factors.append({
            "factor": "Port Scan / Network Reconnaissance",
            "points": points,
            "description": "Observed rapid horizontal or vertical port exploration"
        })
        total_score += points

    if "DGA / DNS Tunneling" in threat_types_seen:
        points = 20.0
        factors.append({
            "factor": "DNS Anomaly / Tunneling Exfiltration",
            "points": points,
            "description": "High entropy query names and suspicious volumetric DNS payloads"
        })
        total_score += points

    if "Botnet C2" in threat_types_seen:
        points = 22.0
        factors.append({
            "factor": "Persistent C2 Beaconing Heartbeat",
            "points": points,
            "description": "Repeated periodic cadence with deterministic interval jitter"
        })
        total_score += points

    if "Data Exfiltration" in threat_types_seen:
        points = 25.0
        factors.append({
            "factor": "Volumetric Data Exfiltration",
            "points": points,
            "description": "Anomalous bulk outbound data transfer exceeding normal baseline"
        })
        total_score += points

    if "DDoS" in threat_types_seen:
        points = 25.0
        factors.append({
            "factor": "Volumetric Denial of Service (DDoS)",
            "points": points,
            "description": "Extreme packet velocity saturation targeting destination"
        })
        total_score += points

    if "Suspicious Encrypted" in threat_types_seen:
        points = 15.0
        factors.append({
            "factor": "Suspicious Encrypted Session",
            "points": points,
            "description": "Anomalous TLS handshake or self-signed certificate"
        })
        total_score += points

    # Contributor 2: Local Threat Intelligence Match
    if threat_intel_match:
        points = 20.0
        factors.append({
            "factor": "Local Threat Intelligence Feed Match",
            "points": points,
            "description": "Host IP matches verified offline adversary indicator"
        })
        total_score += points

    # Contributor 3: Behavioral Baseline Anomaly
    if baseline_anomaly:
        points = 12.0
        factors.append({
            "factor": "Behavioral Baseline Volume Deviation (>300%)",
            "points": points,
            "description": "Entity transmission rate dramatically exceeded learned rolling average"
        })
        total_score += points

    # Contributor 4: Asymmetric Outbound Volume
    if high_outbound:
        points = 8.0
        factors.append({
            "factor": "Asymmetric Outbound Flow Dominance",
            "points": points,
            "description": "Unidirectional data transfer ratio skewed heavily outbound"
        })
        total_score += points

    # Cap at 100.0
    final_score = min(total_score, 100.0)

    # Classify Risk Level
    if final_score >= 80.0:
        level = "CRITICAL"
    elif final_score >= 50.0:
        level = "HIGH"
    elif final_score >= 20.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": round(final_score, 1),
        "risk_level": level,
        "risk_factors": factors
    }

def get_asset_inventory(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Builds real-time asset inventory derived directly from stored flows and alerts.
    """
    # Group flows by src_ip
    src_flows = (
        db.query(
            FlowRecord.src_ip.label("ip"),
            func.count(FlowRecord.id).label("flow_count"),
            func.sum(FlowRecord.total_bytes).label("bytes_out"),
            func.min(FlowRecord.timestamp).label("first_seen"),
            func.max(FlowRecord.timestamp).label("last_seen"),
            func.count(func.distinct(FlowRecord.dst_port)).label("unique_ports"),
            func.count(func.distinct(FlowRecord.dst_ip)).label("unique_destinations")
        )
        .group_by(FlowRecord.src_ip)
        .order_by(desc("flow_count"))
        .limit(limit)
        .all()
    )

    # Fetch all alerts to calculate risk
    all_alerts = db.query(Alert).all()
    alerts_by_ip = {}
    for a in all_alerts:
        if a.src_ip not in alerts_by_ip:
            alerts_by_ip[a.src_ip] = []
        alerts_by_ip[a.src_ip].append(a)

    # Check threat intel
    intel_ips = set(
        db.query(ThreatIntelIndicator.indicator)
        .filter(ThreatIntelIndicator.indicator_type == "IP")
        .all()
    )
    intel_ips = {row[0].strip().lower() for row in intel_ips}

    assets = []
    for row in src_flows:
        ip = row.ip
        ip_alerts = alerts_by_ip.get(ip, [])
        threat_count = len(ip_alerts)

        threat_intel_match = (ip.strip().lower() in intel_ips)
        baseline_anomaly = any("Baseline" in str(a.evidence) for a in ip_alerts)
        high_outbound = (row.bytes_out or 0) > 1_000_000

        risk_data = compute_entity_risk(
            ip=ip,
            alerts=ip_alerts,
            threat_intel_match=threat_intel_match,
            baseline_anomaly=baseline_anomaly,
            high_outbound=high_outbound
        )

        # Inferred role
        role = infer_asset_role(
            ip=ip,
            dst_ports=[],
            threat_count=threat_count,
            bytes_out=row.bytes_out or 0,
            bytes_in=0
        )

        assets.append({
            "ip": ip,
            "role": role,
            "first_observed": row.first_seen.isoformat() if row.first_seen else datetime.now(timezone.utc).isoformat(),
            "last_observed": row.last_seen.isoformat() if row.last_seen else datetime.now(timezone.utc).isoformat(),
            "bytes_in": 0,
            "bytes_out": int(row.bytes_out or 0),
            "flows_count": int(row.flow_count or 0),
            "unique_ports": int(row.unique_ports or 0),
            "destinations_count": int(row.unique_destinations or 0),
            "threat_count": threat_count,
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "risk_factors": risk_data["risk_factors"]
        })

    # Sort by risk score descending
    assets.sort(key=lambda a: a["risk_score"], reverse=True)
    return assets
