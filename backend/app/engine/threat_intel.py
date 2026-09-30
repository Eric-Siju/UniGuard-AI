"""
Local Offline-First Threat Intelligence Engine for UniGuard AI
Strictly passive: evaluates observed indicators against local threat feeds
without outbound egress or external network calls.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from sqlalchemy.orm import Session
from backend.app.models.database import SessionLocal, ThreatIntelIndicator

@dataclass
class ThreatIntelMatch:
    matched: bool
    indicator: str
    indicator_type: str
    source: str
    severity: str
    description: str

class LocalThreatIntelEngine:
    def __init__(self):
        # Pre-seed offline high-fidelity threat indicators for demonstration
        self._default_indicators = [
            {
                "indicator_type": "IP",
                "indicator": "10.0.0.99",
                "description": "Known C2 Command & Control Node (Operation Cobalt Shade)",
                "source": "Local CERT Research Feed",
                "severity": "CRITICAL"
            },
            {
                "indicator_type": "IP",
                "indicator": "198.51.100.45",
                "description": "Exfiltration Drop Server (Adversary APT-29 Infrastructure)",
                "source": "Air-Gap Defense Intelligence",
                "severity": "CRITICAL"
            },
            {
                "indicator_type": "IP",
                "indicator": "192.0.2.188",
                "description": "Known Mirai-Variant Botnet Scanner",
                "source": "Local Baseline Watchlist",
                "severity": "HIGH"
            },
            {
                "indicator_type": "DOMAIN",
                "indicator": "exfil-c2-tunnel.local",
                "description": "Identified DNS Data Tunneling Domain",
                "source": "Internal DNS Sensor Signature",
                "severity": "HIGH"
            },
            {
                "indicator_type": "DOMAIN",
                "indicator": "evil-c2-beacon.corp",
                "description": "Malicious Heartbeat Beacon Rendezvous",
                "source": "Local Threat Advisory",
                "severity": "HIGH"
            },
            {
                "indicator_type": "SNI",
                "indicator": "darkc2.shadow-network.internal",
                "description": "Anomalous Encrypted Channel Hostname",
                "source": "Passive TLS Handshake Fingerprint",
                "severity": "HIGH"
            }
        ]
        self._indicators_cache: Dict[str, Dict[str, Any]] = {}
        self.load_indicators()

    def load_indicators(self):
        """Loads indicators from database and pre-seeds defaults if empty."""
        db = SessionLocal()
        try:
            count = db.query(ThreatIntelIndicator).count()
            if count == 0:
                for item in self._default_indicators:
                    obj = ThreatIntelIndicator(**item)
                    db.add(obj)
                db.commit()

            all_items = db.query(ThreatIntelIndicator).all()
            self._indicators_cache.clear()
            for ind in all_items:
                # Key by lowercase string for rapid O(1) matching
                key = f"{ind.indicator_type.upper()}:{ind.indicator.lower().strip()}"
                self._indicators_cache[key] = {
                    "id": ind.id,
                    "indicator_type": ind.indicator_type,
                    "indicator": ind.indicator,
                    "description": ind.description,
                    "source": ind.source,
                    "severity": ind.severity
                }
        finally:
            db.close()

    def check_flow(self, flow: Dict[str, Any]) -> Optional[ThreatIntelMatch]:
        """
        Passively checks flow attributes against local indicators.
        Evaluates src_ip, dst_ip, dns_query, and sni.
        Zero outbound network access.
        """
        src_ip = str(flow.get("src_ip", "")).strip().lower()
        dst_ip = str(flow.get("dst_ip", "")).strip().lower()
        dns_query = str(flow.get("dns_query", "") or "").strip().lower()
        sni = str(flow.get("sni", "") or "").strip().lower()

        # Check IPs
        for ip in [dst_ip, src_ip]:
            if not ip:
                continue
            key = f"IP:{ip}"
            if key in self._indicators_cache:
                info = self._indicators_cache[key]
                return ThreatIntelMatch(
                    matched=True,
                    indicator=info["indicator"],
                    indicator_type="IP",
                    source=info["source"],
                    severity=info["severity"],
                    description=info["description"]
                )

        # Check DNS queries
        if dns_query:
            # Direct match
            key = f"DOMAIN:{dns_query}"
            if key in self._indicators_cache:
                info = self._indicators_cache[key]
                return ThreatIntelMatch(
                    matched=True,
                    indicator=info["indicator"],
                    indicator_type="DOMAIN",
                    source=info["source"],
                    severity=info["severity"],
                    description=info["description"]
                )
            # Check domain suffix
            for c_key, info in self._indicators_cache.items():
                if c_key.startswith("DOMAIN:"):
                    dom = c_key[7:]
                    if dns_query.endswith(dom) or dom in dns_query:
                        return ThreatIntelMatch(
                            matched=True,
                            indicator=info["indicator"],
                            indicator_type="DOMAIN",
                            source=info["source"],
                            severity=info["severity"],
                            description=info["description"]
                        )

        # Check SNI
        if sni:
            key = f"SNI:{sni}"
            if key in self._indicators_cache:
                info = self._indicators_cache[key]
                return ThreatIntelMatch(
                    matched=True,
                    indicator=info["indicator"],
                    indicator_type="SNI",
                    source=info["source"],
                    severity=info["severity"],
                    description=info["description"]
                )

        return None

    match_flow = check_flow

    def add_indicator(self, indicator_type: str, indicator: str, description: str, source: str, severity: str) -> bool:
        """Adds a local threat indicator."""
        db = SessionLocal()
        try:
            ind_clean = indicator.strip()
            existing = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.indicator == ind_clean).first()
            if existing:
                existing.indicator_type = indicator_type.upper()
                existing.description = description
                existing.source = source
                existing.severity = severity
            else:
                new_ind = ThreatIntelIndicator(
                    indicator_type=indicator_type.upper(),
                    indicator=ind_clean,
                    description=description,
                    source=source,
                    severity=severity
                )
                db.add(new_ind)
            db.commit()
            self.load_indicators()
            return True
        finally:
            db.close()

    def get_all_indicators(self) -> List[Dict[str, Any]]:
        return list(self._indicators_cache.values())

threat_intel = LocalThreatIntelEngine()
threat_intel_engine = threat_intel
