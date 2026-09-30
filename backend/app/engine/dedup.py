"""
Alert Deduplication & Suppression Engine for UniGuard AI
Inspired by Suricata event_filter and Elastic alert suppression.
Prevents alert flooding by aggregating high-frequency identical security events
into a single consolidated alert tracking occurrences, first/last seen times, and targeted ports.
"""

import time
from typing import Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field

@dataclass
class AggregatedAlertState:
    alert_id: str
    threat_type: str
    severity: str
    src_ip: str
    dst_ip: str
    protocol: str
    first_seen: float
    last_seen: float
    occurrences: int = 1
    suppressed_count: int = 0
    ports: Set[int] = field(default_factory=set)

class AlertDeduplicator:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        # Maps (src_ip, dst_ip, threat_type) -> AggregatedAlertState
        self._active_window: Dict[Tuple[str, str, str], AggregatedAlertState] = {}

    def process(
        self,
        alert_dict: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Evaluates an alert for deduplication.
        Returns:
            (alert_payload, is_new_alert)
            If is_new_alert is False, this is a suppressed duplicate with updated occurrence counters.
        """
        now = time.time()
        src_ip = str(alert_dict.get("src_ip", ""))
        dst_ip = str(alert_dict.get("dst_ip", ""))
        threat_type = str(alert_dict.get("threat_type", ""))
        port = int(alert_dict.get("dst_port", 0) or 0)

        key = (src_ip, dst_ip, threat_type)

        if key in self._active_window:
            state = self._active_window[key]
            # Check if still within suppression window
            if (now - state.last_seen) <= self.window_seconds:
                state.occurrences += 1
                state.suppressed_count += 1
                state.last_seen = now
                if port > 0:
                    state.ports.add(port)

                # Return updated payload for existing alert
                updated_payload = dict(alert_dict)
                updated_payload["alert_id"] = state.alert_id
                updated_payload["occurrences"] = state.occurrences
                updated_payload["suppressed_count"] = state.suppressed_count
                updated_payload["first_seen"] = state.first_seen
                updated_payload["last_seen"] = state.last_seen
                
                # Append deduplication evidence
                updated_payload["evidence"] = list(alert_dict.get("evidence", [])) + [
                    f"[Alert Suppression] {state.occurrences} identical events aggregated in {self.window_seconds:.0f}s window "
                    f"({state.suppressed_count} suppressed duplicates, {len(state.ports)} ports targeted)."
                ]
                return updated_payload, False

        # New alert window
        state = AggregatedAlertState(
            alert_id=alert_dict["alert_id"],
            threat_type=threat_type,
            severity=alert_dict.get("severity", "MEDIUM"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=str(alert_dict.get("protocol", "TCP")),
            first_seen=now,
            last_seen=now,
            occurrences=1,
            suppressed_count=0,
            ports={port} if port > 0 else set()
        )
        self._active_window[key] = state

        new_payload = dict(alert_dict)
        new_payload["occurrences"] = 1
        new_payload["suppressed_count"] = 0
        new_payload["first_seen"] = now
        new_payload["last_seen"] = now
        return new_payload, True

    def cleanup_old_windows(self):
        """Cleans up states older than 2x window duration."""
        now = time.time()
        to_del = [k for k, v in self._active_window.items() if (now - v.last_seen) > (self.window_seconds * 2)]
        for k in to_del:
            del self._active_window[k]

deduplicator = AlertDeduplicator(window_seconds=60.0)
