"""
Synthetic Traffic Generator for Unidirectional Flow Simulation
Generates realistic normal baseline and 6 distinct cyber threat flow datasets
strictly offline and locally for evaluation, training, and real-time demonstration.
"""

import os
import random
import string
import time
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np
from pathlib import Path
from backend.app.core.config import DATA_DIR

NORMAL_DOMAINS = [
    "updates.microsoft.com", "api.github.com", "cdn.cloudflare.com",
    "dns.google", "aws.amazon.com", "repo.maven.apache.org",
    "registry.npmjs.org", "pypi.org", "internal.corp.local"
]

DGA_CHARS = string.ascii_lowercase + string.digits

def random_ip(prefix: str = "192.168.1.") -> str:
    return f"{prefix}{random.randint(10, 250)}"

def random_public_ip() -> str:
    first = random.choice([23, 45, 52, 104, 142, 185, 198])
    return f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_normal_flows(count: int = 300, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 3600
    flows = []
    
    internal_ips = [f"10.0.1.{i}" for i in range(10, 30)]
    external_servers = [random_public_ip() for _ in range(15)]
    
    t = base_time
    for i in range(count):
        t += random.uniform(0.5, 3.0)
        src = random.choice(internal_ips)
        dst = random.choice(external_servers)
        proto = random.choices(["TCP", "UDP", "DNS"], weights=[0.75, 0.15, 0.10])[0]
        
        if proto == "TCP":
            dst_port = random.choice([80, 443, 8080, 8443, 22])
            duration = random.uniform(0.2, 5.0)
            pkts = random.randint(4, 30)
            bytes_val = pkts * random.randint(200, 1400)
            flags = "SA" if random.random() > 0.1 else "S"
            dns_q = None
            sni = random.choice(NORMAL_DOMAINS) if dst_port in [443, 8443] else None
        elif proto == "DNS":
            dst_port = 53
            duration = random.uniform(0.01, 0.08)
            pkts = random.randint(2, 4)
            bytes_val = random.randint(120, 350)
            flags = ""
            dns_q = random.choice(NORMAL_DOMAINS)
            sni = None
        else:
            dst_port = random.choice([123, 161, 500])
            duration = random.uniform(0.05, 0.5)
            pkts = random.randint(2, 8)
            bytes_val = pkts * random.randint(60, 200)
            flags = ""
            dns_q = None
            sni = None
            
        flows.append({
            "flow_id": f"norm_{i}_{int(t*1000)}",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(30000, 65000),
            "dst_port": dst_port,
            "protocol": proto,
            "duration": round(duration, 4),
            "total_bytes": bytes_val,
            "total_packets": pkts,
            "tcp_flags": flags,
            "dns_query": dns_q,
            "sni": sni,
            "threat_label": "Normal",
            "ts_epoch": t
        })
    return flows

def generate_ddos_flows(count: int = 250, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 2500
    flows = []
    target_server = "10.0.1.50"
    target_port = 80
    
    t = base_time
    for i in range(count):
        t += random.uniform(0.005, 0.05)
        src = random_public_ip()
        duration = random.uniform(0.01, 0.1)
        pkts = random.randint(30, 150)
        bytes_val = pkts * random.randint(40, 80)
        
        flows.append({
            "flow_id": f"ddos_{i}_{int(t*1000)}",
            "src_ip": src,
            "dst_ip": target_server,
            "src_port": random.randint(1024, 65535),
            "dst_port": target_port,
            "protocol": "TCP",
            "duration": round(duration, 4),
            "total_bytes": bytes_val,
            "total_packets": pkts,
            "tcp_flags": "S",
            "dns_query": None,
            "sni": None,
            "threat_label": "DDoS",
            "ts_epoch": t
        })
    return flows

def generate_port_scan_flows(count: int = 250, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 2000
    flows = []
    attacker_ip = "192.168.1.185"
    target_subnets = [f"10.0.1.{i}" for i in range(1, 15)]
    scan_ports = list(range(20, 1024, 4)) + [1433, 3306, 3389, 5432, 8080, 8443, 9200]
    
    t = base_time
    for i in range(count):
        t += random.uniform(0.02, 0.12)
        dst_ip = random.choice(target_subnets)
        dst_port = scan_ports[i % len(scan_ports)]
        duration = random.uniform(0.005, 0.08)
        
        flows.append({
            "flow_id": f"scan_{i}_{int(t*1000)}",
            "src_ip": attacker_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(40000, 60000),
            "dst_port": dst_port,
            "protocol": "TCP",
            "duration": round(duration, 4),
            "total_bytes": 128,
            "total_packets": 2,
            "tcp_flags": "S",
            "dns_query": None,
            "sni": None,
            "threat_label": "Port Scan",
            "ts_epoch": t
        })
    return flows

def generate_botnet_flows(count: int = 200, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 1800
    flows = []
    compromised_hosts = ["10.0.1.14", "10.0.1.22", "10.0.1.28"]
    c2_servers = ["194.26.29.112", "185.220.101.5"]
    
    t = base_time
    for i in range(count):
        jitter = random.gauss(0, 0.03)
        t += 5.0 + jitter
        src = random.choice(compromised_hosts)
        c2 = random.choice(c2_servers)
        duration = random.uniform(0.1, 0.3)
        pkts = random.randint(4, 6)
        bytes_val = random.randint(180, 240)
        
        flows.append({
            "flow_id": f"bot_{i}_{int(t*1000)}",
            "src_ip": src,
            "dst_ip": c2,
            "src_port": random.randint(45000, 55000),
            "dst_port": 8443,
            "protocol": "TCP",
            "duration": round(duration, 4),
            "total_bytes": bytes_val,
            "total_packets": pkts,
            "tcp_flags": "PA",
            "dns_query": None,
            "sni": "c2-control-node.net",
            "threat_label": "Botnet C2",
            "ts_epoch": t
        })
    return flows

def generate_dns_tunneling_flows(count: int = 220, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 1500
    flows = []
    compromised_client = "10.0.1.19"
    dns_resolver = "10.0.1.2"
    
    t = base_time
    for i in range(count):
        t += random.uniform(0.3, 1.5)
        chunk_len = random.randint(24, 45)
        data_chunk = "".join(random.choices(DGA_CHARS, k=chunk_len))
        sub_label = "".join(random.choices(DGA_CHARS, k=8))
        query = f"{data_chunk}.{sub_label}.covert-tunnel.org"
        duration = random.uniform(0.02, 0.15)
        
        flows.append({
            "flow_id": f"dns_{i}_{int(t*1000)}",
            "src_ip": compromised_client,
            "dst_ip": dns_resolver,
            "src_port": random.randint(50000, 60000),
            "dst_port": 53,
            "protocol": "DNS",
            "duration": round(duration, 4),
            "total_bytes": random.randint(250, 480),
            "total_packets": 2,
            "tcp_flags": "",
            "dns_query": query,
            "sni": None,
            "threat_label": "DGA / DNS Tunneling",
            "ts_epoch": t
        })
    return flows

def generate_encrypted_threat_flows(count: int = 200, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 1200
    flows = []
    compromised_endpoint = "10.0.1.33"
    rogue_relay = "146.70.157.42"
    
    t = base_time
    for i in range(count):
        t += random.uniform(1.0, 4.0)
        bad_port = random.choice([4444, 9001, 1337, 31337, 8888])
        duration = random.uniform(5.0, 45.0)
        pkts = random.randint(40, 180)
        bytes_val = pkts * random.randint(300, 800)
        
        flows.append({
            "flow_id": f"enc_{i}_{int(t*1000)}",
            "src_ip": compromised_endpoint,
            "dst_ip": rogue_relay,
            "src_port": random.randint(49000, 61000),
            "dst_port": bad_port,
            "protocol": "TLS",
            "duration": round(duration, 4),
            "total_bytes": bytes_val,
            "total_packets": pkts,
            "tcp_flags": "PA",
            "dns_query": None,
            "sni": "secure-gateway-sync.xyz",
            "threat_label": "Suspicious Encrypted Traffic",
            "ts_epoch": t
        })
    return flows

def generate_exfiltration_flows(count: int = 180, base_time: Optional[float] = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time() - 800
    flows = []
    insider_host = "10.0.1.15"
    external_drop = "91.215.85.17"
    
    t = base_time
    for i in range(count):
        t += random.uniform(2.0, 8.0)
        duration = random.uniform(10.0, 90.0)
        bytes_val = random.randint(6_000_000, 35_000_000)
        pkts = bytes_val // 1420
        
        flows.append({
            "flow_id": f"exfil_{i}_{int(t*1000)}",
            "src_ip": insider_host,
            "dst_ip": external_drop,
            "src_port": random.randint(48000, 59000),
            "dst_port": random.choice([443, 8080, 21]),
            "protocol": "TCP",
            "duration": round(duration, 4),
            "total_bytes": bytes_val,
            "total_packets": pkts,
            "tcp_flags": "PA",
            "dns_query": None,
            "sni": "backup-cloud-vault.com",
            "threat_label": "Data Exfiltration",
            "ts_epoch": t
        })
    return flows

def generate_all_sample_datasets():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    base_t = time.time() - 7200
    
    print("[+] Generating normal baseline traffic...")
    normal_flows = generate_normal_flows(count=400, base_time=base_t)
    pd.DataFrame(normal_flows).to_csv(DATA_DIR / "normal.csv", index=False)
    
    print("[+] Generating DDoS flows...")
    ddos_flows = generate_ddos_flows(count=300, base_time=base_t + 5)
    pd.DataFrame(ddos_flows).to_csv(DATA_DIR / "ddos.csv", index=False)
    
    print("[+] Generating Port Scan flows...")
    scan_flows = generate_port_scan_flows(count=300, base_time=base_t + 10)
    pd.DataFrame(scan_flows).to_csv(DATA_DIR / "port_scan.csv", index=False)
    
    print("[+] Generating Botnet C2 beacon flows...")
    botnet_flows = generate_botnet_flows(count=250, base_time=base_t + 15)
    pd.DataFrame(botnet_flows).to_csv(DATA_DIR / "botnet.csv", index=False)
    
    print("[+] Generating DGA / DNS Tunneling flows...")
    dns_flows = generate_dns_tunneling_flows(count=250, base_time=base_t + 20)
    pd.DataFrame(dns_flows).to_csv(DATA_DIR / "dns_tunneling.csv", index=False)
    
    print("[+] Generating Suspicious Encrypted flows...")
    enc_flows = generate_encrypted_threat_flows(count=250, base_time=base_t + 25)
    pd.DataFrame(enc_flows).to_csv(DATA_DIR / "encrypted_traffic.csv", index=False)
    
    print("[+] Generating Data Exfiltration flows...")
    exfil_flows = generate_exfiltration_flows(count=200, base_time=base_t + 30)
    pd.DataFrame(exfil_flows).to_csv(DATA_DIR / "exfiltration.csv", index=False)
    
    print("[+] Generating combined interleaved demo dataset...")
    all_combined = (
        normal_flows +
        scan_flows +
        ddos_flows +
        botnet_flows +
        dns_flows +
        enc_flows +
        exfil_flows
    )
    all_combined.sort(key=lambda x: x["ts_epoch"])
    df_combined = pd.DataFrame(all_combined)
    df_combined.to_csv(DATA_DIR / "combined_demo.csv", index=False)
    
    print(f"[?] Generated {len(df_combined)} total records across all datasets in {DATA_DIR}")

if __name__ == "__main__":
    generate_all_sample_datasets()
