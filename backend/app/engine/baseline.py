"""
Behavioral Baseline & Temporal Anomaly Engine for UniGuard AI
Maintains dynamic rolling baselines of host and protocol behavior over time
to detect statistical shifts and traffic anomalies.
"""

import time
from typing import Dict, Any, Optional
from collections import defaultdict, deque
import numpy as np

class EntityBaseline:
    def __init__(self, ip: str):
        self.ip = ip
        # Sliding history of observations (max 50 observations)
        self.flow_timestamps = deque(maxlen=60)
        self.packet_rates = deque(maxlen=30)
        self.byte_rates = deque(maxlen=30)
        self.dst_ips = deque(maxlen=50)
        self.dst_ports = deque(maxlen=50)
        self.total_bytes_sent = 0
        self.total_flows_count = 0
        self.created_at = time.time()

    def add_observation(self, flow: Dict[str, Any], features: Dict[str, float]):
        now = float(flow.get("ts_epoch", time.time()))
        self.flow_timestamps.append(now)
        self.total_flows_count += 1
        
        pps = float(features.get("packets_per_sec", flow.get("packets_per_sec", 1.0)))
        bps = float(features.get("bytes_per_sec", flow.get("bytes_per_sec", 100.0)))
        dst_ip = str(flow.get("dst_ip", ""))
        dst_port = int(flow.get("dst_port", 0) or 0)
        
        self.packet_rates.append(pps)
        self.byte_rates.append(bps)
        if dst_ip:
            self.dst_ips.append(dst_ip)
        if dst_port:
            self.dst_ports.append(dst_port)
        self.total_bytes_sent += int(flow.get("total_bytes", 0) or 0)

    @property
    def status(self) -> str:
        """Returns baseline learning warm-up state."""
        return "BASELINE READY" if len(self.packet_rates) >= 5 else "LEARNING BASELINE"

    def get_baseline_stats(self) -> Dict[str, float]:
        if len(self.packet_rates) < 5:
            return {
                "avg_pps": float(np.mean(self.packet_rates)) if self.packet_rates else 10.0,
                "avg_bps": float(np.mean(self.byte_rates)) if self.byte_rates else 1000.0,
                "flows_per_min": 15.0,
                "dst_diversity": 1.0
            }
        
        # Estimate flows per minute from timestamp window
        if len(self.flow_timestamps) >= 2:
            time_span = max(self.flow_timestamps[-1] - self.flow_timestamps[0], 1.0)
            fpm = (len(self.flow_timestamps) / time_span) * 60.0
        else:
            fpm = 20.0

        return {
            "avg_pps": float(np.mean(self.packet_rates)),
            "avg_bps": float(np.mean(self.byte_rates)),
            "flows_per_min": max(round(fpm, 1), 5.0),
            "dst_diversity": len(set(self.dst_ips)) / max(len(self.dst_ips), 1)
        }

class BehavioralBaselineEngine:
    def __init__(self):
        self.entity_baselines: Dict[str, EntityBaseline] = defaultdict(EntityBaseline)

    def record_flow(self, flow: Dict[str, Any], features: Dict[str, float]):
        src_ip = str(flow.get("src_ip", "")).strip()
        if src_ip:
            if src_ip not in self.entity_baselines:
                self.entity_baselines[src_ip] = EntityBaseline(src_ip)
            self.entity_baselines[src_ip].add_observation(flow, features)

    def evaluate_deviation(self, flow: Dict[str, Any], features: Dict[str, float]) -> Optional[Dict[str, Any]]:
        """
        Evaluates current flow against the entity's rolling baseline.
        Returns deviation metrics and formatted explanation if an anomaly is observed.
        """
        src_ip = str(flow.get("src_ip", "")).strip()
        if not src_ip or src_ip not in self.entity_baselines:
            return None

        baseline = self.entity_baselines[src_ip]
        if baseline.status != "BASELINE READY":
            return {
                "status": "LEARNING BASELINE",
                "observations": len(baseline.packet_rates),
                "is_significant": False,
                "deviation_percent": 0.0,
                "summary": "Baseline engine in learning warm-up state (< 5 samples)"
            }

        stats = baseline.get_baseline_stats()
        current_pps = float(features.get("packets_per_sec", flow.get("packets_per_sec", 1.0)))
        current_bps = float(features.get("bytes_per_sec", flow.get("bytes_per_sec", 100.0)))
        current_fpm = stats["flows_per_min"]

        # Calculate deviation against baseline
        pps_baseline = max(stats["avg_pps"], 5.0)
        pps_ratio = current_pps / pps_baseline
        bps_baseline = max(stats["avg_bps"], 500.0)
        bps_ratio = current_bps / bps_baseline

        max_ratio = max(pps_ratio, bps_ratio)
        deviation_pct = (max_ratio - 1.0) * 100.0

        is_significant = max_ratio >= 3.0  # 300% or greater spike above normal baseline

        # Format user-friendly NSM baseline deviation explanation
        if pps_ratio >= bps_ratio and pps_ratio >= 2.0:
            summary = (
                f"CURRENT: {current_pps:.1f} pkts/sec | BASELINE: {pps_baseline:.1f} pkts/sec | "
                f"DEVIATION: +{deviation_pct:.0f}%"
            )
        elif bps_ratio >= 2.0:
            summary = (
                f"CURRENT: {current_bps/1024:.1f} KB/sec | BASELINE: {bps_baseline/1024:.1f} KB/sec | "
                f"DEVIATION: +{deviation_pct:.0f}%"
            )
        else:
            summary = (
                f"CURRENT: {current_fpm:.0f} flows/min | BASELINE: {stats['flows_per_min']:.0f} flows/min | "
                f"NORMAL RANGE"
            )

        return {
            "status": "BASELINE READY",
            "is_significant": is_significant,
            "deviation_percent": round(deviation_pct, 1),
            "summary": summary,
            "baseline_stats": stats,
            "current_metrics": {
                "pps": round(current_pps, 1),
                "bps": round(current_bps, 1),
                "flows_per_min": round(current_fpm, 1)
            }
        }

baseline_engine = BehavioralBaselineEngine()
