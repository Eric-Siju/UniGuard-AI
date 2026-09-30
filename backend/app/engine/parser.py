"""
Passive Traffic Parsers for PCAP and CSV Data
Extracts unidirectional flow metadata and packets without payload decryption or active network probing.
"""

import os
import io
import time
import pandas as pd
from typing import List, Dict, Any, Generator, Optional
from backend.app.engine.flow_aggregator import UnidirectionalFlowAggregator

# Scapy import for PCAP passive inspection
try:
    from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CSV_COLUMN_MAPPINGS = {
    "src_ip": ["src_ip", "source_ip", "srcaddr", "saddr", "ipv4_src_addr", "source ip", "src"],
    "dst_ip": ["dst_ip", "destination_ip", "dstaddr", "daddr", "ipv4_dst_addr", "destination ip", "dst"],
    "src_port": ["src_port", "source_port", "sport", "l4_src_port", "source port"],
    "dst_port": ["dst_port", "destination_port", "dport", "l4_dst_port", "destination port"],
    "protocol": ["protocol", "proto", "ip_proto", "transport"],
    "duration": ["duration", "flow_duration", "dur", "flow duration"],
    "total_bytes": ["total_bytes", "bytes", "tot_bytes", "in_bytes", "totbytes", "byte_count"],
    "total_packets": ["total_packets", "packets", "tot_pkts", "in_pkts", "totpkts", "packet_count"],
    "tcp_flags": ["tcp_flags", "flags", "tcp_flag", "tcpflags"],
    "dns_query": ["dns_query", "dns", "query", "domain", "qname"],
    "sni": ["sni", "server_name", "tls_sni"],
    "threat_label": ["threat_label", "threat", "label", "attack", "class", "attack_cat"]
}

def normalize_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalizes arbitrary column names in a dataframe to the standard UniGuard schema."""
    col_map = {}
    lower_cols = {col.lower().strip(): col for col in df.columns}
    
    for standard_name, aliases in CSV_COLUMN_MAPPINGS.items():
        matched = False
        for alias in aliases:
            if alias in lower_cols:
                col_map[lower_cols[alias]] = standard_name
                matched = True
                break
                
    df_renamed = df.rename(columns=col_map)
    
    # Fill standard defaults if missing
    if "src_ip" not in df_renamed.columns:
        df_renamed["src_ip"] = "192.168.1.100"
    if "dst_ip" not in df_renamed.columns:
        df_renamed["dst_ip"] = "10.0.0.1"
    if "src_port" not in df_renamed.columns:
        df_renamed["src_port"] = 49152
    if "dst_port" not in df_renamed.columns:
        df_renamed["dst_port"] = 80
    if "protocol" not in df_renamed.columns:
        df_renamed["protocol"] = "TCP"
    if "duration" not in df_renamed.columns:
        df_renamed["duration"] = 1.0
    if "total_bytes" not in df_renamed.columns:
        df_renamed["total_bytes"] = 512
    if "total_packets" not in df_renamed.columns:
        df_renamed["total_packets"] = 4
    if "threat_label" not in df_renamed.columns:
        df_renamed["threat_label"] = "Normal"
        
    # Clean data types
    df_renamed["src_port"] = pd.to_numeric(df_renamed["src_port"], errors="coerce").fillna(0).astype(int)
    df_renamed["dst_port"] = pd.to_numeric(df_renamed["dst_port"], errors="coerce").fillna(0).astype(int)
    df_renamed["duration"] = pd.to_numeric(df_renamed["duration"], errors="coerce").fillna(0.001)
    df_renamed["total_bytes"] = pd.to_numeric(df_renamed["total_bytes"], errors="coerce").fillna(0).astype(int)
    df_renamed["total_packets"] = pd.to_numeric(df_renamed["total_packets"], errors="coerce").fillna(1).astype(int)
    
    return df_renamed

def parse_csv_file(file_path: str) -> List[Dict[str, Any]]:
    """Loads and parses a CSV flow file into normalized flow dictionaries."""
    df = pd.read_csv(file_path)
    df = normalize_csv_columns(df)
    flows = []
    
    for idx, row in df.iterrows():
        flow = {
            "flow_id": f"csv_flow_{idx}_{int(time.time())}",
            "src_ip": str(row.get("src_ip", "10.0.0.1")),
            "dst_ip": str(row.get("dst_ip", "10.0.0.2")),
            "src_port": int(row.get("src_port", 0)),
            "dst_port": int(row.get("dst_port", 0)),
            "protocol": str(row.get("protocol", "TCP")).upper(),
            "duration": float(row.get("duration", 0.1)),
            "total_bytes": int(row.get("total_bytes", 500)),
            "total_packets": int(row.get("total_packets", 5)),
            "tcp_flags": str(row.get("tcp_flags", "S" if row.get("protocol") == "TCP" else "")),
            "dns_query": str(row.get("dns_query")) if pd.notna(row.get("dns_query")) else None,
            "sni": str(row.get("sni")) if pd.notna(row.get("sni")) else None,
            "threat_label": str(row.get("threat_label", "Normal")),
            "ts_epoch": time.time()
        }
        flows.append(flow)
    return flows

def parse_pcap_file(file_path: str, max_packets: int = 20000) -> List[Dict[str, Any]]:
    """
    Passively extracts unidirectional packet observations from a PCAP file
    using Scapy and aggregates them into flows.
    Strictly passive: extracts packet headers and TLS SNI / DNS queries without decryption.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. PCAP parsing requires Scapy.")
        
    aggregator = UnidirectionalFlowAggregator(flow_timeout=2.0)
    packet_count = 0
    completed_flows = []
    
    with PcapReader(file_path) as pcap_reader:
        for pkt in pcap_reader:
            packet_count += 1
            if packet_count > max_packets:
                break
                
            ts = float(pkt.time)
            length = len(pkt)
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            flags = ""
            dns_q = None
            sni_val = None
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue  # Skip non-IP frames in passive IP monitoring
                
            if TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags.flagrepr()
                
                # Check for TLS ClientHello SNI safely without decrypting
                if dst_port in [443, 8443] and len(pkt[TCP].payload) > 5:
                    payload = bytes(pkt[TCP].payload)
                    # Content Type 22 is Handshake, Handshake Type 1 is ClientHello
                    if len(payload) > 9 and payload[0] == 0x16 and payload[5] == 0x01:
                        # Extract server name safely from SNI extension
                        try:
                            # Quick scan for extension type 0x0000 (server_name)
                            idx = payload.find(b"\x00\x00")
                            if idx != -1 and idx + 7 < len(payload):
                                sni_len = int.from_bytes(payload[idx+5:idx+7], "big")
                                if 0 < sni_len < 255 and idx + 7 + sni_len <= len(payload):
                                    sni_val = payload[idx+7:idx+7+sni_len].decode("ascii", errors="ignore")
                        except Exception:
                            pass
                            
            elif UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                
                # Passive DNS metadata extraction
                if (src_port == 53 or dst_port == 53) and DNS in pkt:
                    protocol = "DNS"
                    if pkt[DNS].qd and DNSQR in pkt[DNS].qd:
                        try:
                            dns_q = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        except Exception:
                            dns_q = str(pkt[DNS].qd.qname)
                            
            elif ICMP in pkt:
                protocol = "ICMP"
                
            flow = aggregator.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                timestamp=ts,
                flags=flags,
                dns_query=dns_q,
                sni=sni_val
            )
            if flow:
                completed_flows.append(flow)
                
    # Flush remaining active flows
    remaining = aggregator.flush_all()
    completed_flows.extend(remaining)
    return completed_flows
