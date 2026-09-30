"""
Attack Campaign Correlation Engine for UniGuard AI
Correlates multi-phase security events from the same observed entity over time
into consolidated attack campaign narratives (Reconnaissance -> C2 -> DNS -> Exfiltration).
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.models.database import Alert

PHASE_MAPPING = {
    "Port Scan": {
        "phase": "Phase 1: Reconnaissance",
        "tactic": "Network Discovery",
        "description": "Probing infrastructure for accessible attack surfaces",
        "weight": 20
    },
    "Botnet C2": {
        "phase": "Phase 2: Command & Control",
        "tactic": "C2 Channel Establishment",
        "description": "Establishing periodic heartbeat beacons to control servers",
        "weight": 25
    },
    "Suspicious Encrypted": {
        "phase": "Phase 2: Command & Control",
        "tactic": "Encrypted Signaling",
        "description": "Establishing anomalous TLS session for obfuscated communications",
        "weight": 20
    },
    "DGA / DNS Tunneling": {
        "phase": "Phase 3: DNS Manipulation",
        "tactic": "Protocol Concealment / Tunneling",
        "description": "Encoding payload data in DNS TXT/A queries or DGA lookups",
        "weight": 25
    },
    "Data Exfiltration": {
        "phase": "Phase 4: Data Exfiltration",
        "tactic": "Impact & Data Staging",
        "description": "Asymmetric bulk exfiltration of sensitive assets outward",
        "weight": 30
    },
    "DDoS": {
        "phase": "Phase 5: Denial of Service",
        "tactic": "Disruption & Diversion",
        "description": "Volumetric packet flooding to exhaust perimeter capacity",
        "weight": 30
    }
}

class AttackCampaignCorrelator:
    def get_campaigns(self, db: Session) -> List[Dict[str, Any]]:
        """
        Groups alerts by source IP to identify multi-stage attack campaigns.
        An entity with 2 or more distinct threat classes is identified as a correlated campaign.
        """
        alerts = db.query(Alert).order_by(Alert.timestamp.asc()).all()
        by_src: Dict[str, List[Alert]] = {}
        for a in alerts:
            if a.src_ip not in by_src:
                by_src[a.src_ip] = []
            by_src[a.src_ip].append(a)

        campaigns: List[Dict[str, Any]] = []
        campaign_counter = 1

        for src_ip, alert_list in by_src.items():
            distinct_types = set(a.threat_type for a in alert_list)
            # Only formulate campaign if at least 2 distinct threat classes or 5+ critical/high alerts
            if len(distinct_types) >= 2 or len(alert_list) >= 4:
                phases = []
                seen_phases = set()
                total_risk_points = 0
                
                timeline = []
                for a in alert_list:
                    mapping = PHASE_MAPPING.get(a.threat_type, {
                        "phase": "General Threat Activity",
                        "tactic": "Unknown",
                        "description": "Suspicious network event",
                        "weight": 10
                    })
                    phase_name = mapping["phase"]
                    if phase_name not in seen_phases:
                        seen_phases.add(phase_name)
                        phases.append({
                            "phase_name": phase_name,
                            "threat_type": a.threat_type,
                            "tactic": mapping["tactic"],
                            "description": mapping["description"]
                        })
                    total_risk_points += mapping["weight"]
                    
                    timeline.append({
                        "alert_id": a.alert_id,
                        "threat_type": a.threat_type,
                        "severity": a.severity,
                        "timestamp": a.timestamp.isoformat() if a.timestamp else datetime.now(timezone.utc).isoformat(),
                        "target": f"{a.dst_ip}:{a.dst_port}",
                        "evidence": a.evidence[:2] if a.evidence else []
                    })

                campaign_risk = min(40 + total_risk_points, 98)
                campaign_id = f"CAMPAIGN-{campaign_counter:03d}"
                campaign_counter += 1

                # Progression title
                title = f"Correlated Multi-Phase Activity from {src_ip}"
                if "Data Exfiltration" in distinct_types and "Port Scan" in distinct_types:
                    title = f"Multi-Stage Cyber Intrusion: Reconnaissance to Exfiltration ({src_ip})"
                elif "Botnet C2" in distinct_types:
                    title = f"Active C2 Infrastructure Campaign ({src_ip})"

                campaigns.append({
                    "campaign_id": campaign_id,
                    "title": title,
                    "entity_ip": src_ip,
                    "threat_count": len(alert_list),
                    "distinct_stages": len(phases),
                    "campaign_risk": campaign_risk,
                    "status": "ACTIVE INVESTIGATION",
                    "phases": phases,
                    "timeline": timeline,
                    "created_at": alert_list[0].timestamp.isoformat() if alert_list[0].timestamp else datetime.now(timezone.utc).isoformat(),
                    "updated_at": alert_list[-1].timestamp.isoformat() if alert_list[-1].timestamp else datetime.now(timezone.utc).isoformat(),
                    "recommended_action": "Isolate source IP and prioritize forensic case escalation."
                })

        # Sort by campaign risk descending
        campaigns.sort(key=lambda c: c["campaign_risk"], reverse=True)
        return campaigns

campaign_correlator = AttackCampaignCorrelator()
campaign_engine = campaign_correlator
