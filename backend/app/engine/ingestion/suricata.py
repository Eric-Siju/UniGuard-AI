"""
Suricata EVE JSON Log Ingestion Adapter for UniGuard AI
Normalizes Suricata EVE JSON events (flow, alert, dns, tls, anomaly) into UniGuard internal schema.
"""

import json
import uuid
from typing import Dict, Any, List, Optional
from backend.app.engine.ingestion.base import BaseIngestionAdapter

class SuricataEveAdapter(BaseIngestionAdapter):
    source_type: str = "SURICATA_EVE"

    def parse_content(self, raw_text: str) -> List[Dict[str, Any]]:
        normalized_flows = []
        lines = raw_text.strip().splitlines()

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            self.records_received += 1
            try:
                record = json.loads(line)
            except Exception as e:
                self.records_rejected += 1
                if len(self.parsing_errors) < 20:
                    self.parsing_errors.append(f"Line {line_num}: JSON decode error ({str(e)})")
                continue

            try:
                flow = self._normalize_eve(record)
                if flow:
                    normalized_flows.append(flow)
                    self.records_parsed += 1
                else:
                    self.records_rejected += 1
            except Exception as e:
                self.records_rejected += 1
                if len(self.parsing_errors) < 20:
                    self.parsing_errors.append(f"Line {line_num}: EVE parsing error ({str(e)})")

        return normalized_flows

    def _normalize_eve(self, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = r.get("event_type", "flow")
        flow_id = str(r.get("flow_id") or f"eve-{uuid.uuid4().hex[:12]}")
        
        src_ip = str(r.get("src_ip") or "")
        dst_ip = str(r.get("dest_ip") or "")
        src_port = int(r.get("src_port") or 0)
        dst_port = int(r.get("dest_port") or 0)

        if not src_ip or not dst_ip:
            return None

        proto = str(r.get("proto") or "TCP").upper()
        
        flow_data = r.get("flow", {})
        bytes_toserver = int(flow_data.get("bytes_toserver") or 0)
        bytes_toclient = int(flow_data.get("bytes_toclient") or 0)
        total_bytes = max(bytes_toserver + bytes_toclient, 64)
        
        pkts_toserver = int(flow_data.get("pkts_toserver") or 1)
        pkts_toclient = int(flow_data.get("pkts_toclient") or 0)
        total_packets = max(pkts_toserver + pkts_toclient, 1)

        duration = 0.5
        if "age" in flow_data:
            duration = float(flow_data.get("age") or 0.5)

        dur_safe = max(duration, 0.001)
        pps = total_packets / dur_safe
        bps = total_bytes / dur_safe

        # DNS event
        dns_query = None
        if event_type == "dns" or "dns" in r:
            dns_info = r.get("dns", {})
            dns_query = dns_info.get("rrname") or dns_info.get("query")
            proto = "DNS"

        # TLS event
        sni = None
        is_encrypted = (dst_port in [443, 8443])
        if event_type == "tls" or "tls" in r:
            tls_info = r.get("tls", {})
            sni = tls_info.get("sni")
            is_encrypted = True

        # External Alert check
        external_alert = None
        if event_type == "alert":
            alert_info = r.get("alert", {})
            sig = alert_info.get("signature", "Suricata Alert")
            external_alert = {
                "signature": sig,
                "category": alert_info.get("category", "General Threat"),
                "severity": alert_info.get("severity", 3)
            }

        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "duration": round(duration, 4),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "tcp_flags": "SYN,ACK" if proto == "TCP" else "",
            "dns_query": dns_query,
            "sni": sni,
            "is_encrypted": is_encrypted,
            "threat_label": "Normal",
            "risk_score": 0.0,
            "source_format": "Suricata EVE",
            "external_alert": external_alert
        }
