"""
Unidirectional Flow Aggregator
Passively aggregates raw network packets from TAP/Diode into structured unidirectional flows.
Computes flow duration, packet timing statistics, TCP flag distribution, and protocol metadata.
Strictly passive: no packet retransmissions, no active handshakes.
"""

import time
import math
from typing import Dict, Any, List, Optional
from collections import defaultdict
import numpy as np

class FlowBucket:
    """Holds packet observations for an individual unidirectional flow."""
    def __init__(self, key: tuple, first_seen: float):
        self.key = key  # (src_ip, dst_ip, src_port, dst_port, protocol)
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.packet_count = 0
        self.byte_count = 0
        self.packet_lengths: List[int] = []
        self.timestamps: List[float] = []
        self.tcp_flags = set()
        self.dns_query: Optional[str] = None
        self.sni: Optional[str] = None
        self.is_encrypted = False

    def add_packet(self, length: int, ts: float, flags: str = "", dns_q: str = None, sni_val: str = None):
        self.packet_count += 1
        self.byte_count += length
        self.packet_lengths.append(length)
        self.timestamps.append(ts)
        self.last_seen = ts
        
        for char in flags:
            self.tcp_flags.add(char.upper())
            
        if dns_q and not self.dns_query:
            self.dns_query = dns_q
        if sni_val and not self.sni:
            self.sni = sni_val
            self.is_encrypted = True

    def to_flow_dict(self) -> Dict[str, Any]:
        src_ip, dst_ip, src_port, dst_port, protocol = self.key
        duration = max(self.last_seen - self.first_seen, 0.0001)
        
        # Calculate Inter-Arrival Times (IAT)
        if len(self.timestamps) > 1:
            iats = np.diff(self.timestamps)
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_min = 0.0
            iat_max = 0.0

        # Packet length statistics
        if self.packet_lengths:
            avg_packet_size = float(np.mean(self.packet_lengths))
            packet_size_std = float(np.std(self.packet_lengths))
        else:
            avg_packet_size = 0.0
            packet_size_std = 0.0

        flags_str = "".join(sorted(list(self.tcp_flags)))
        syn_count = 1 if "S" in flags_str else 0
        ack_count = 1 if "A" in flags_str else 0
        rst_count = 1 if "R" in flags_str else 0

        # Port-based encrypted inference
        if dst_port in [443, 8443, 853, 993, 995, 465] or protocol == "TLS" or self.sni:
            self.is_encrypted = True

        return {
            "flow_id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}_{int(self.first_seen*1000)}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "duration": round(duration, 4),
            "total_bytes": self.byte_count,
            "total_packets": self.packet_count,
            "packets_per_sec": round(self.packet_count / duration, 2),
            "bytes_per_sec": round(self.byte_count / duration, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "packet_size_std": round(packet_size_std, 2),
            "iat_mean": round(iat_mean, 4),
            "iat_std": round(iat_std, 4),
            "iat_min": round(iat_min, 4),
            "iat_max": round(iat_max, 4),
            "tcp_flags": flags_str,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "dns_query": self.dns_query,
            "sni": self.sni,
            "is_encrypted": self.is_encrypted,
            "ts_epoch": self.first_seen
        }

class UnidirectionalFlowAggregator:
    """
    Maintains active flows and exports completed flows based on timeout.
    """
    def __init__(self, flow_timeout: float = 3.0):
        self.flow_timeout = flow_timeout
        self.active_flows: Dict[tuple, FlowBucket] = {}

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: int,
        timestamp: Optional[float] = None,
        flags: str = "",
        dns_query: Optional[str] = None,
        sni: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        ts = timestamp if timestamp is not None else time.time()
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        completed_flow = None
        if key in self.active_flows:
            bucket = self.active_flows[key]
            if (ts - bucket.last_seen) > self.flow_timeout:
                # Flow timed out; export previous flow and start a new one
                completed_flow = bucket.to_flow_dict()
                bucket = FlowBucket(key, ts)
                self.active_flows[key] = bucket
            bucket.add_packet(length, ts, flags, dns_query, sni)
        else:
            bucket = FlowBucket(key, ts)
            bucket.add_packet(length, ts, flags, dns_query, sni)
            self.active_flows[key] = bucket
            
        return completed_flow

    def flush_expired(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        now = current_time if current_time is not None else time.time()
        expired = []
        keys_to_remove = []
        for key, bucket in self.active_flows.items():
            if (now - bucket.last_seen) >= self.flow_timeout:
                expired.append(bucket.to_flow_dict())
                keys_to_remove.append(key)
        for k in keys_to_remove:
            del self.active_flows[k]
        return expired

    def flush_all(self) -> List[Dict[str, Any]]:
        all_flows = [bucket.to_flow_dict() for bucket in self.active_flows.values()]
        self.active_flows.clear()
        return all_flows
