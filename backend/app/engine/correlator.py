"""
Transparent Threat Correlation & Risk Severity Engine
Synthesizes Multi-Signal Rules, Supervised Random Forest Probabilities,
and Unsupervised Isolation Forest Anomaly Scores into Explainable Security Alerts.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from backend.app.engine.rules import RuleMatch

@dataclass
class CorrelatedThreat:
    alert_id: str
    timestamp: float
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 - 1.0
    risk_score: float  # 0.0 - 100.0
    evidence: List[str]
    rule_matches: List[str]
    ml_prediction: str
    ml_confidence: float
    contributing_features: List[Dict[str, Any]]
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    total_bytes: int
    total_packets: int
    anomaly_score: float

class ThreatCorrelator:
    """
    Transparent Correlation Engine.
    Combines rule evidence, ML probabilities, and anomaly detection.
    """
    def correlate(
        self,
        flow: Dict[str, Any],
        features: Dict[str, float],
        rule_matches: List[RuleMatch],
        ml_result: Dict[str, Any]
    ) -> Optional[CorrelatedThreat]:
        
        ml_class = ml_result.get("prediction", "Normal")
        ml_conf = float(ml_result.get("confidence", 0.0))
        anomaly_score = float(ml_result.get("anomaly_score", 0.0))
        is_anomaly = ml_result.get("is_anomaly", False)
        
        # If no rules fired, ML predicts Normal, and no anomaly -> benign traffic
        if not rule_matches and ml_class == "Normal" and not is_anomaly:
            return None
            
        evidence_list = []
        rule_ids = [m.rule_id for m in rule_matches]
        
        # Collect evidence from all triggered rules
        for match in rule_matches:
            for ev in match.evidence:
                if ev not in evidence_list:
                    evidence_list.append(f"[Rule Engine ({match.rule_id})] {ev}")
                    
        # Determine Primary Threat Class
        threat_type = "Normal"
        base_confidence = 0.50
        
        if rule_matches:
            # Sort by rule confidence
            best_rule = max(rule_matches, key=lambda m: m.confidence)
            threat_type = best_rule.threat_class
            base_confidence = best_rule.confidence
            
            # Corroboration check: Did ML model agree with the rule?
            if ml_class == threat_type:
                # Corroborating signals: boost confidence
                correlation_bonus = min(ml_conf * 0.15, 0.20)
                final_confidence = min(base_confidence + correlation_bonus, 0.99)
                evidence_list.append(
                    f"[Correlation Corroboration] Machine Learning ({ml_class}) strongly confirmed "
                    f"Rule Engine detection with {ml_conf*100:.1f}% confidence."
                )
            else:
                # Rule fired but ML differed: slight discount
                final_confidence = max(base_confidence - 0.05, 0.55)
                evidence_list.append(
                    f"[Correlation Signal] Rule Engine flagged {threat_type} while ML model ranked "
                    f"{ml_class} ({ml_conf*100:.1f}%). Multi-signal behavioral heuristics prioritized."
                )
        else:
            # ML or Anomaly detected threat without strict rule match
            if ml_class != "Normal" and ml_conf >= 0.70:
                threat_type = ml_class
                final_confidence = ml_conf * 0.90
                evidence_list.append(
                    f"[ML Random Forest] Multi-class classifier identified {threat_type} "
                    f"pattern with {ml_conf*100:.1f}% statistical confidence."
                )
            elif is_anomaly:
                threat_type = "Suspicious Zero-Day Anomaly"
                final_confidence = max(anomaly_score * 0.85, 0.60)
                evidence_list.append(
                    f"[Isolation Forest] High feature space deviation detected (Anomaly Score: {anomaly_score:.2f})."
                )
            else:
                return None
                
        # If primary threat remains Normal, drop alert
        if threat_type == "Normal":
            return None
            
        # Add contributing feature explanations from Explainable AI
        contributions = ml_result.get("contributing_features", [])
        if contributions:
            top_f = contributions[0]
            evidence_list.append(
                f"[Explainable AI] Primary discriminating feature: '{top_f['name']}' "
                f"(Observed value: {top_f['value']:.2f}, model importance weight: {top_f['importance']:.3f})."
            )
            
        # Compute Transparent Risk Score (0 - 100)
        # Base risk from threat category severity
        threat_base_risk = {
            "DDoS": 85.0,
            "Data Exfiltration": 90.0,
            "Botnet C2": 75.0,
            "Port Scan": 55.0,
            "DGA / DNS Tunneling": 70.0,
            "Suspicious Encrypted Traffic": 65.0,
            "Suspicious Zero-Day Anomaly": 60.0
        }.get(threat_type, 50.0)
        
        # Factor in confidence and volumetric impact
        confidence_factor = final_confidence
        tot_bytes = float(flow.get("total_bytes", 0))
        volume_factor = min(tot_bytes / 5_000_000, 1.0) * 10.0  # up to +10 points for massive flows
        
        raw_risk = (threat_base_risk * 0.70) + (confidence_factor * 20.0) + volume_factor
        risk_score = round(min(max(raw_risk, 10.0), 99.5), 1)
        
        # Map Risk Score to Standard Severity
        if risk_score >= 82.0:
            severity = "CRITICAL"
        elif risk_score >= 65.0:
            severity = "HIGH"
        elif risk_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        alert_id = f"ALT-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
        
        return CorrelatedThreat(
            alert_id=alert_id,
            timestamp=flow.get("ts_epoch", time.time()),
            threat_type=threat_type,
            severity=severity,
            confidence=round(final_confidence, 2),
            risk_score=risk_score,
            evidence=evidence_list,
            rule_matches=rule_ids,
            ml_prediction=ml_class,
            ml_confidence=round(ml_conf, 2),
            contributing_features=contributions,
            flow_id=flow.get("flow_id", str(uuid.uuid4())),
            src_ip=flow.get("src_ip", "0.0.0.0"),
            dst_ip=flow.get("dst_ip", "0.0.0.0"),
            src_port=int(flow.get("src_port", 0)),
            dst_port=int(flow.get("dst_port", 0)),
            protocol=flow.get("protocol", "TCP"),
            duration=float(flow.get("duration", 0.0)),
            total_bytes=int(flow.get("total_bytes", 0)),
            total_packets=int(flow.get("total_packets", 0)),
            anomaly_score=anomaly_score
        )

# Global singleton correlator
threat_correlator = ThreatCorrelator()
