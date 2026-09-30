"""
Multi-Signal Rule Engine for Passive Threat Detection
Evaluates flows against multiple corroborating network behavioral signals.
Strictly passive: relies only on unidirectional header observations and statistical dynamics.
"""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from backend.app.core.config import settings

@dataclass
class RuleMatch:
    rule_id: str
    threat_class: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 - 1.0
    evidence: List[str]
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: float = field(default_factory=time.time)

class BaseRule:
    rule_id: str = "BASE"
    threat_class: str = "Unknown"
    
    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        raise NotImplementedError

class DDoSRule(BaseRule):
    rule_id: str = "RULE-DDOS-01"
    threat_class: str = "DDoS"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        pps = features.get("packets_per_sec", 0.0)
        bps = features.get("bytes_per_sec", 0.0)
        syn_ratio = features.get("syn_ratio", 0.0)
        fan_in = features.get("fan_in", 1.0)
        tot_pkts = features.get("total_packets", 0.0)
        
        # Signal 1: High packet rate
        if pps >= settings.DDOS_PACKET_RATE_THRESHOLD:
            evidence.append(f"Abnormal packet velocity: {pps:.1f} pkts/sec (threshold: {settings.DDOS_PACKET_RATE_THRESHOLD})")
            signals += 1
            
        # Signal 2: SYN flood behaviour
        if syn_ratio >= settings.DDOS_SYN_RATIO_THRESHOLD and tot_pkts > 10:
            evidence.append(f"Severe SYN skew: {syn_ratio*100:.1f}% SYN packets without complete handshakes")
            signals += 1
            
        # Signal 3: Extreme volumetric bandwidth
        if bps >= 500_000:  # > 500 KB/sec on single flow
            evidence.append(f"Extreme volumetric transfer: {bps/1024:.1f} KB/sec")
            signals += 1
            
        # Signal 4: Fan-in convergence to single destination
        if fan_in >= 15:
            evidence.append(f"High destination convergence (Fan-in: {int(fan_in)} distinct sources targeting host)")
            signals += 1
            
        # Multi-signal evaluation
        if signals >= 2:
            confidence = min(0.60 + (signals * 0.12), 0.98)
            severity = "CRITICAL" if signals >= 3 or pps > 600 else "HIGH"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("protocol", "")
            )
        return None

class PortScanRule(BaseRule):
    rule_id: str = "RULE-PORTSCAN-02"
    threat_class: str = "Port Scan"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        fan_out = features.get("fan_out", 1.0)
        unique_ports = features.get("unique_dst_ports", 1.0)
        duration = features.get("duration", 0.0)
        conn_freq = features.get("conn_frequency", 1.0)
        syn_ratio = features.get("syn_ratio", 0.0)
        
        # Signal 1: High port or destination diversity
        if unique_ports >= settings.PORT_SCAN_PORT_THRESHOLD:
            evidence.append(f"High port sweep: {int(unique_ports)} distinct destination ports contacted by source")
            signals += 1
        elif fan_out >= settings.PORT_SCAN_FAN_OUT_THRESHOLD:
            evidence.append(f"Horizontal sweep: {int(fan_out)} distinct hosts targeted by source")
            signals += 1
            
        # Signal 2: Short probe durations
        if duration < 0.2 and flow.get("total_packets", 0) <= 3:
            evidence.append(f"Short reconnaissance probe duration: {duration*1000:.1f}ms")
            signals += 1
            
        # Signal 3: Unacknowledged connection attempts
        if syn_ratio >= 0.70:
            evidence.append(f"Incomplete connection probing: SYN ratio {syn_ratio*100:.1f}%")
            signals += 1
            
        # Signal 4: Rapid connection rate
        if conn_freq >= 10.0:
            evidence.append(f"Rapid probing cadence: {conn_freq:.1f} connection attempts/sec")
            signals += 1
            
        if signals >= 2:
            confidence = min(0.65 + (signals * 0.10), 0.96)
            severity = "HIGH" if unique_ports >= 30 or fan_out >= 20 else "MEDIUM"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("protocol", "")
            )
        return None

class BotnetBeaconRule(BaseRule):
    rule_id: str = "RULE-BOTNET-03"
    threat_class: str = "Botnet C2"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        iat_std = features.get("iat_std", 1.0)
        iat_mean = features.get("iat_mean", 0.0)
        tot_bytes = features.get("total_bytes", 0.0)
        tot_pkts = features.get("total_packets", 0.0)
        avg_pkt = features.get("avg_packet_size", 0.0)
        
        # Signal 1: Highly periodic intervals (low jitter)
        if 0.5 <= iat_mean <= 60.0 and iat_std <= settings.BOTNET_INTERVAL_JITTER_MAX and tot_pkts >= 3:
            evidence.append(f"Strict periodic heartbeat: interval {iat_mean:.2f}s with minimal jitter (std dev {iat_std:.3f}s)")
            signals += 1
            
        # Signal 2: Small, uniform telemetry beacon payload
        if 40 <= avg_pkt <= 250 and tot_bytes < 5000:
            evidence.append(f"Fixed-size heartbeat payload: {avg_pkt:.1f} bytes avg")
            signals += 1
            
        # Signal 3: Repetitive communication pattern
        if tot_pkts >= 3 and flow.get("dst_port") in [443, 8080, 8443, 4444, 9001]:
            evidence.append(f"Persistent C2 control channel on port {flow.get('dst_port')}")
            signals += 1

        if signals >= 2:
            confidence = min(0.60 + (signals * 0.12), 0.95)
            severity = "HIGH" if signals >= 3 else "MEDIUM"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("protocol", "")
            )
        return None

class DNSTunnelingRule(BaseRule):
    rule_id: str = "RULE-DNS-04"
    threat_class: str = "DGA / DNS Tunneling"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        dns_query = flow.get("dns_query") or ""
        dns_entropy = features.get("dns_entropy", 0.0)
        dns_len = features.get("dns_query_length", 0.0)
        digit_ratio = features.get("dns_digit_ratio", 0.0)
        subdomains = features.get("dns_subdomain_depth", 0.0)
        
        if not dns_query and flow.get("protocol") != "DNS" and flow.get("dst_port") != 53:
            return None
            
        # Signal 1: High Shannon entropy in domain string
        if dns_entropy >= settings.DNS_ENTROPY_THRESHOLD:
            evidence.append(f"Elevated domain entropy: {dns_entropy:.2f} bits (threshold: {settings.DNS_ENTROPY_THRESHOLD})")
            signals += 1
            
        # Signal 2: Unusual domain length (data chunk encoded in subdomain)
        if dns_len >= settings.DNS_LENGTH_THRESHOLD:
            evidence.append(f"Excessive domain length: {int(dns_len)} characters (threshold: {settings.DNS_LENGTH_THRESHOLD})")
            signals += 1
            
        # Signal 3: Abnormal digit / hex character ratio
        if digit_ratio >= 0.25:
            evidence.append(f"High numeric/hex ratio in query: {digit_ratio*100:.1f}%")
            signals += 1
            
        # Signal 4: Deep subdomain labels
        if subdomains >= 3:
            evidence.append(f"Abnormal label depth: {int(subdomains)} subdomains in {dns_query}")
            signals += 1
            
        if signals >= 2:
            confidence = min(0.65 + (signals * 0.10), 0.97)
            severity = "HIGH" if dns_entropy > 4.0 or dns_len > 45 else "MEDIUM"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("protocol", "")
            )
        return None

class SuspiciousEncryptedRule(BaseRule):
    rule_id: str = "RULE-ENCRYPTED-05"
    threat_class: str = "Suspicious Encrypted Traffic"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        dst_port = int(flow.get("dst_port", 0))
        is_encrypted = flow.get("is_encrypted", False)
        duration = features.get("duration", 0.0)
        bps = features.get("bytes_per_sec", 0.0)
        iat_std = features.get("iat_std", 0.0)
        tot_bytes = features.get("total_bytes", 0.0)
        
        # Signal 1: TLS / encrypted communication on non-standard ports
        if is_encrypted and dst_port not in [443, 8443, 853]:
            evidence.append(f"Encrypted TLS payload observed on non-standard port: {dst_port}")
            signals += 1
            
        # Signal 2: Unusual timing bursts without web browser interactivity
        if is_encrypted and iat_std < 0.05 and tot_bytes > 20000:
            evidence.append("Synchronous automated encrypted transfer without interactive human jitter")
            signals += 1
            
        # Signal 3: Long sustained encrypted tunnel with steady small payloads
        if is_encrypted and duration > 60.0 and bps < 2000:
            evidence.append(f"Long-lived encrypted covert channel: {duration:.1f}s duration")
            signals += 1

        if signals >= 2:
            confidence = min(0.60 + (signals * 0.15), 0.92)
            severity = "HIGH" if signals >= 3 else "MEDIUM"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=dst_port,
                protocol=flow.get("protocol", "")
            )
        return None

class DataExfiltrationRule(BaseRule):
    rule_id: str = "RULE-EXFIL-06"
    threat_class: str = "Data Exfiltration"

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[RuleMatch]:
        evidence = []
        signals = 0
        
        outbound_bytes = features.get("outbound_bytes", 0.0)
        outbound_ratio = features.get("outbound_ratio", 1.0)
        bps = features.get("bytes_per_sec", 0.0)
        duration = features.get("duration", 0.0)
        
        # Signal 1: High volumetric outbound data transfer
        if outbound_bytes >= settings.EXFILTRATION_BYTES_THRESHOLD:
            evidence.append(f"Massive outbound transfer volume: {outbound_bytes / (1024*1024):.2f} MB")
            signals += 1
            
        # Signal 2: Asymmetric unidirectional upload ratio
        if outbound_ratio >= settings.EXFILTRATION_RATIO_THRESHOLD:
            evidence.append(f"Extreme upload asymmetry: {outbound_ratio:.1f}:1 outbound-to-inbound ratio")
            signals += 1
            
        # Signal 3: Sustained egress bandwidth rate
        if bps >= 200_000 and duration >= 5.0:
            evidence.append(f"Sustained high egress speed: {bps/1024:.1f} KB/sec for {duration:.1f}s")
            signals += 1

        if signals >= 2:
            confidence = min(0.70 + (signals * 0.10), 0.98)
            severity = "CRITICAL" if outbound_bytes > 10_000_000 else "HIGH"
            return RuleMatch(
                rule_id=self.rule_id,
                threat_class=self.threat_class,
                severity=severity,
                confidence=round(confidence, 2),
                evidence=evidence,
                flow_id=flow.get("flow_id", ""),
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("protocol", "")
            )
        return None

class RuleEngine:
    """Master Multi-Signal Rule Engine orchestrating all individual threat rules."""
    def __init__(self):
        self.rules: List[BaseRule] = [
            DDoSRule(),
            PortScanRule(),
            BotnetBeaconRule(),
            DNSTunnelingRule(),
            SuspiciousEncryptedRule(),
            DataExfiltrationRule()
        ]

    def evaluate_flow(self, flow: Dict[str, Any], features: Dict[str, float]) -> List[RuleMatch]:
        matches = []
        for rule in self.rules:
            match = rule.evaluate(flow, features)
            if match:
                matches.append(match)
        return matches
