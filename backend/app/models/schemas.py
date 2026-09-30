"""
Pydantic Schemas for Request/Response Validation
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class FlowRecordSchema(BaseModel):
    id: Optional[int] = None
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    total_bytes: int
    total_packets: int
    packets_per_sec: float
    bytes_per_sec: float
    tcp_flags: Optional[str] = ""
    dns_query: Optional[str] = None
    sni: Optional[str] = None
    is_encrypted: bool = False
    threat_label: str = "Normal"
    risk_score: float = 0.0

    class Config:
        from_attributes = True

class AlertSchema(BaseModel):
    id: Optional[int] = None
    alert_id: str
    timestamp: datetime
    threat_type: str
    severity: str
    confidence: float
    risk_score: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    total_bytes: int
    total_packets: int
    evidence: List[str] = []
    rule_matches: List[str] = []
    ml_prediction: Optional[str] = ""
    ml_confidence: Optional[float] = 0.0
    contributing_features: List[Dict[str, Any]] = []
    flow_id: str
    acknowledged: bool = False

    class Config:
        from_attributes = True

class ThreatSummarySchema(BaseModel):
    total_threats: int
    threat_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    top_attackers: List[Dict[str, Any]]
    top_targeted_ports: List[Dict[str, Any]]
    recent_timeline: List[Dict[str, Any]]

class SystemStatsSchema(BaseModel):
    flows_processed: int
    packets_processed: int
    threats_detected: int
    suspicious_flows: int
    current_risk_level: str
    processing_latency_ms: float
    packets_per_sec: float
    flows_per_sec: float
    cpu_percent: float
    memory_mb: float
    passive_mode: bool = True
    read_only_status: bool = True
    active_response: bool = False

class ModelEvaluationSchema(BaseModel):
    model_name: str
    model_type: str
    version: str
    training_timestamp: datetime
    dataset_name: str
    feature_count: int
    classes: List[str]
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]]
    classification_report: Dict[str, Any]
    false_positive_rate: float
    false_negative_rate: float
    top_features: List[Dict[str, Any]]
    is_active: bool

class StreamControlRequest(BaseModel):
    action: Optional[str] = 'start'  # start, pause, resume, stop
    speed: Optional[float] = 1.0
    scenario: Optional[str] = 'combined_demo'
    dataset: Optional[str] = None
    speed_factor: Optional[float] = None

class StreamStatusSchema(BaseModel):
    state: str  # STOPPED, RUNNING, PAUSED
    speed: float
    scenario: str
    flows_streamed: int
    threats_streamed: int

class SettingsUpdateRequest(BaseModel):
    ddos_packet_rate_threshold: Optional[float] = None
    ddos_syn_ratio_threshold: Optional[float] = None
    port_scan_port_threshold: Optional[int] = None
    botnet_interval_jitter_max: Optional[float] = None
    dns_entropy_threshold: Optional[float] = None
    dns_length_threshold: Optional[int] = None
    exfiltration_bytes_threshold: Optional[int] = None
    stream_interval: Optional[float] = None