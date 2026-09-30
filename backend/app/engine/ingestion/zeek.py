"""
Zeek JSON Log Ingestion Adapter for UniGuard AI
Normalizes Zeek conn.log, dns.log, and ssl.log JSON outputs into UniGuard internal schema.
"""

import json
import uuid
from typing import Dict, Any, List, Optional
from backend.app.engine.ingestion.base import BaseIngestionAdapter

class ZeekJsonAdapter(BaseIngestionAdapter):
    source_type: str = "ZEEK_JSON"

    def parse_content(self, raw_text: str) -> List[Dict[str, Any]]:
        normalized_flows = []
        lines = raw_text.strip().splitlines()

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            self.records_received += 1
            try:
                record = json.loads(line)
            except Exception as e:
                self.records_rejected += 1
                if len(self.parsing_errors) < 20:
                    self.parsing_errors.append(f"Line {line_num}: JSON decode error ({str(e)})")
                continue

            # Identify if it is conn.log, dns.log, or ssl.log
            try:
                flow = self._normalize_record(record)
                if flow:
                    normalized_flows.append(flow)
                    self.records_parsed += 1
                else:
                    self.records_rejected += 1
            except Exception as e:
                self.records_rejected += 1
                if len(self.parsing_errors) < 20:
                    self.parsing_errors.append(f"Line {line_num}: Normalization error ({str(e)})")

        return normalized_flows

    def _normalize_record(self, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        uid = str(r.get("uid") or f"zeek-{uuid.uuid4().hex[:12]}")
        
        # Zeek standard field names for conn / dns / ssl
        src_ip = str(r.get("id.orig_h") or r.get("orig_h") or r.get("src_ip") or "")
        dst_ip = str(r.get("id.resp_h") or r.get("resp_h") or r.get("dst_ip") or "")
        src_port = int(r.get("id.orig_p") or r.get("orig_p") or r.get("src_port") or 0)
        dst_port = int(r.get("id.resp_p") or r.get("resp_p") or r.get("dst_port") or 0)
        
        if not src_ip or not dst_ip:
            return None

        proto = str(r.get("proto") or "tcp").upper()
        duration = float(r.get("duration") or 0.0)
        
        orig_bytes = int(r.get("orig_bytes") or r.get("orig_ip_bytes") or 0)
        resp_bytes = int(r.get("resp_bytes") or r.get("resp_ip_bytes") or 0)
        tot_bytes = orig_bytes + resp_bytes
        
        orig_pkts = int(r.get("orig_pkts") or 1)
        resp_pkts = int(r.get("resp_pkts") or 0)
        tot_pkts = max(orig_pkts + resp_pkts, 1)

        dur_safe = max(duration, 0.001)
        pps = tot_pkts / dur_safe
        bps = tot_bytes / dur_safe

        # DNS metadata
        dns_query = r.get("query")
        if not dns_query and dst_port == 53:
            proto = "DNS"

        # SSL metadata
        sni = r.get("server_name")
        is_encrypted = (dst_port == 443 or bool(sni) or "ssl" in r.get("service", ""))

        conn_state = str(r.get("conn_state") or "")
        tcp_flags = "SYN" if "S0" in conn_state else ("ACK" if "SF" in conn_state else "")

        return {
            "flow_id": uid,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "duration": round(duration, 4),
            "total_bytes": tot_bytes,
            "total_packets": tot_pkts,
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "tcp_flags": tcp_flags,
            "dns_query": dns_query,
            "sni": sni,
            "is_encrypted": is_encrypted,
            "threat_label": "Normal",
            "risk_score": 0.0,
            "source_format": "Zeek JSON"
        }
