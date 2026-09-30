"""
Feature Extraction Engine for Unidirectional IP Flows
Extracts comprehensive statistical, behavioural, protocol, DNS, and TLS features
without payload decryption or active network probing.
"""

import math
import numpy as np
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
import time

def calculate_shannon_entropy(text: Optional[str]) -> float:
    """Calculates Shannon entropy of a string (e.g. DNS domain or SNI)."""
    if not text or not isinstance(text, str):
        return 0.0
    text_clean = text.lower().strip()
    if not text_clean or text_clean == "nan":
        return 0.0
    freq = defaultdict(int)
    for c in text_clean:
        freq[c] += 1
    length = len(text_clean)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)

class NetworkContextTracker:
    """
    Tracks sliding-window network context (fan-in, fan-out, port diversity,
    connection frequencies) across passive unidirectional observations.
    """
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.history = deque(maxlen=window_size)
        self.src_to_dsts = defaultdict(lambda: defaultdict(int))
        self.src_to_ports = defaultdict(lambda: defaultdict(int))
        self.dst_to_srcs = defaultdict(lambda: defaultdict(int))
        self.dst_to_ports = defaultdict(lambda: defaultdict(int))
        self.src_history = defaultdict(lambda: deque(maxlen=50))
    
    def reset(self):
        """Resets all sliding-window tracking state."""
        self.history.clear()
        self.src_to_dsts.clear()
        self.src_to_ports.clear()
        self.dst_to_srcs.clear()
        self.dst_to_ports.clear()
        self.src_history.clear()

    def update(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float):
        if len(self.history) == self.window_size:
            old_src, old_dst, old_port, _ = self.history[0]
            self.src_to_dsts[old_src][old_dst] -= 1
            if self.src_to_dsts[old_src][old_dst] <= 0:
                del self.src_to_dsts[old_src][old_dst]
            self.src_to_ports[old_src][old_port] -= 1
            if self.src_to_ports[old_src][old_port] <= 0:
                del self.src_to_ports[old_src][old_port]
            self.dst_to_srcs[old_dst][old_src] -= 1
            if self.dst_to_srcs[old_dst][old_src] <= 0:
                del self.dst_to_srcs[old_dst][old_src]
            self.dst_to_ports[old_dst][old_port] -= 1
            if self.dst_to_ports[old_dst][old_port] <= 0:
                del self.dst_to_ports[old_dst][old_port]

        self.history.append((src_ip, dst_ip, dst_port, timestamp))
        self.src_to_dsts[src_ip][dst_ip] += 1
        self.src_to_ports[src_ip][dst_port] += 1
        self.dst_to_srcs[dst_ip][src_ip] += 1
        self.dst_to_ports[dst_ip][dst_port] += 1
        self.src_history[src_ip].append(timestamp)
    
    def get_context(self, src_ip: str, dst_ip: str) -> Dict[str, Any]:
        fan_out = len(self.src_to_dsts.get(src_ip, {}))
        unique_dst_ports = len(self.src_to_ports.get(src_ip, {}))
        fan_in = len(self.dst_to_srcs.get(dst_ip, {}))
        unique_src_ports = len(self.dst_to_ports.get(dst_ip, {}))
        
        src_times = list(self.src_history.get(src_ip, []))
        if len(src_times) >= 2:
            time_span = max(src_times[-1] - src_times[0], 0.001)
            conn_frequency = round(len(src_times) / time_span, 2)
        else:
            conn_frequency = 1.0

        return {
            "fan_out": max(fan_out, 1),
            "unique_dst_ports": max(unique_dst_ports, 1),
            "fan_in": max(fan_in, 1),
            "unique_src_ports": max(unique_src_ports, 1),
            "conn_frequency": min(conn_frequency, 500.0),
            "src_diversity": max(fan_in, 1),
            "dst_diversity": max(fan_out, 1)
        }

network_context = NetworkContextTracker()

FEATURE_COLUMNS = [
    "duration",
    "total_bytes",
    "total_packets",
    "packets_per_sec",
    "bytes_per_sec",
    "avg_packet_size",
    "packet_size_std",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "fan_in",
    "fan_out",
    "unique_dst_ports",
    "unique_src_ports",
    "conn_frequency",
    "syn_count",
    "ack_count",
    "rst_count",
    "syn_ratio",
    "dns_query_length",
    "dns_entropy",
    "dns_digit_ratio",
    "dns_subdomain_depth",
    "outbound_bytes",
    "outbound_ratio"
]

def extract_flow_features(
    flow: Dict[str, Any],
    update_context: bool = True,
    tracker: Optional[NetworkContextTracker] = None
) -> Dict[str, float]:
    """
    Extracts numerical feature vector from a raw or aggregated flow dict.
    Returns dictionary with all canonical FEATURE_COLUMNS.
    """
    src_ip = str(flow.get("src_ip", "0.0.0.0"))
    dst_ip = str(flow.get("dst_ip", "0.0.0.0"))
    try:
        dst_port = int(flow.get("dst_port", 0))
    except (ValueError, TypeError):
        dst_port = 0
    try:
        current_ts = float(flow.get("ts_epoch", time.time()))
    except (ValueError, TypeError):
        current_ts = time.time()
    
    active_tracker = tracker if tracker is not None else network_context
    if update_context:
        active_tracker.update(src_ip, dst_ip, dst_port, current_ts)
        ctx = active_tracker.get_context(src_ip, dst_ip)
    else:
        ctx = {
            "fan_out": float(flow.get("fan_out", 1)),
            "unique_dst_ports": float(flow.get("unique_dst_ports", 1)),
            "fan_in": float(flow.get("fan_in", 1)),
            "unique_src_ports": float(flow.get("unique_src_ports", 1)),
            "conn_frequency": float(flow.get("conn_frequency", 1.0)),
        }
    
    try:
        duration = max(float(flow.get("duration", 0.0)), 0.0001)
    except (ValueError, TypeError):
        duration = 0.0001
        
    try:
        total_bytes = int(flow.get("total_bytes", flow.get("bytes", 0)))
    except (ValueError, TypeError):
        total_bytes = 0
        
    try:
        total_packets = max(int(flow.get("total_packets", flow.get("packets", 1))), 1)
    except (ValueError, TypeError):
        total_packets = 1
    
    packets_per_sec = float(flow.get("packets_per_sec", total_packets / duration))
    bytes_per_sec = float(flow.get("bytes_per_sec", total_bytes / duration))
    avg_packet_size = float(flow.get("avg_packet_size", total_bytes / total_packets))
    packet_size_std = float(flow.get("packet_size_std", 0.0))
    
    # Inter-arrival times
    iat_mean = float(flow.get("iat_mean", duration / max(total_packets - 1, 1)))
    iat_std = float(flow.get("iat_std", 0.0))
    iat_min = float(flow.get("iat_min", 0.0))
    iat_max = float(flow.get("iat_max", duration))
    
    # TCP flags safe extraction
    tcp_flags_raw = flow.get("tcp_flags")
    flags_str = str(tcp_flags_raw).upper() if isinstance(tcp_flags_raw, str) and str(tcp_flags_raw).lower() != "nan" else ""
    syn_count = int(flow.get("syn_count", 1 if "S" in flags_str else 0))
    ack_count = int(flow.get("ack_count", 1 if "A" in flags_str else 0))
    rst_count = int(flow.get("rst_count", 1 if "R" in flags_str else 0))
    syn_ratio = float(syn_count / max(syn_count + ack_count + rst_count, 1))
    
    # DNS analysis safe extraction
    dns_raw = flow.get("dns_query")
    if isinstance(dns_raw, str) and str(dns_raw).lower() != "nan":
        dns_query = str(dns_raw).strip()
    else:
        dns_query = ""
        
    dns_query_len = len(dns_query)
    dns_entropy = calculate_shannon_entropy(dns_query)
    dns_digit_ratio = sum(c.isdigit() for c in dns_query) / max(dns_query_len, 1)
    dns_subdomain_depth = len(dns_query.split(".")) - 1 if dns_query else 0
    
    # Exfiltration stats
    outbound_bytes = float(flow.get("outbound_bytes", total_bytes))
    inbound_bytes = float(flow.get("inbound_bytes", max(total_bytes * 0.02, 1.0)))
    outbound_ratio = float(flow.get("outbound_ratio", outbound_bytes / inbound_bytes))
    
    features = {
        "duration": round(duration, 4),
        "total_bytes": float(total_bytes),
        "total_packets": float(total_packets),
        "packets_per_sec": round(packets_per_sec, 2),
        "bytes_per_sec": round(bytes_per_sec, 2),
        "avg_packet_size": round(avg_packet_size, 2),
        "packet_size_std": round(packet_size_std, 2),
        "iat_mean": round(iat_mean, 4),
        "iat_std": round(iat_std, 4),
        "iat_min": round(iat_min, 4),
        "iat_max": round(iat_max, 4),
        "fan_in": float(ctx["fan_in"]),
        "fan_out": float(ctx["fan_out"]),
        "unique_dst_ports": float(ctx["unique_dst_ports"]),
        "unique_src_ports": float(ctx["unique_src_ports"]),
        "conn_frequency": float(ctx["conn_frequency"]),
        "syn_count": float(syn_count),
        "ack_count": float(ack_count),
        "rst_count": float(rst_count),
        "syn_ratio": round(syn_ratio, 4),
        "dns_query_length": float(dns_query_len),
        "dns_entropy": round(dns_entropy, 4),
        "dns_digit_ratio": round(dns_digit_ratio, 4),
        "dns_subdomain_depth": float(dns_subdomain_depth),
        "outbound_bytes": round(outbound_bytes, 2),
        "outbound_ratio": round(outbound_ratio, 2)
    }
    return features
