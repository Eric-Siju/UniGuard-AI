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
    
    # Enhanced SOC fields
    status: Optional[str] = "NEW"
    analyst_note: Optional[str] = ""
    tags: Optional[List[str]] = []
    updated_at: Optional[datetime] = None
    occurrences: Optional[int] = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    suppressed_count: Optional[int] = 0
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    baseline_deviation: Optional[str] = None
    threat_intel_match: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class AlertLifecycleUpdate(BaseModel):
    status: Optional[str] = None  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED
    analyst_note: Optional[str] = None
    tags: Optional[List[str]] = None

class CaseCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "MEDIUM"
    related_alerts: Optional[List[str]] = []
    related_assets: Optional[List[str]] = []
    tags: Optional[List[str]] = []
    analyst_note: Optional[str] = None

class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    new_note: Optional[str] = None
    add_alerts: Optional[List[str]] = None
    remove_alerts: Optional[List[str]] = None

class CaseSchema(BaseModel):
    id: Optional[int] = None
    case_id: str
    title: str
    description: str
    status: str
    severity: str
    created_at: datetime
    updated_at: datetime
    related_alerts: List[str] = []
    related_assets: List[str] = []
    analyst_notes: List[Dict[str, Any]] = []
    tags: List[str] = []

    class Config:
        from_attributes = True

class ThreatIntelIndicatorSchema(BaseModel):
    id: Optional[int] = None
    indicator_type: str
    indicator: str
    description: Optional[str] = ""
    source: Optional[str] = "Local Threat Intel"
    severity: Optional[str] = "HIGH"
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AssetRiskFactor(BaseModel):
    factor: str
    points: float
    description: str

class AssetSchema(BaseModel):
    ip: str
    role: str  # SERVER, CLIENT, DNS, GATEWAY, SUSPICIOUS, UNKNOWN (Inferred)
    first_observed: str
    last_observed: str
    bytes_in: int
    bytes_out: int
    flows_count: int
    unique_ports: int
    destinations_count: int
    threat_count: int
    risk_score: float
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: List[AssetRiskFactor] = []

class ThreatHuntQuery(BaseModel):
    time_window: Optional[str] = "all"  # 15m, 1h, 6h, 24h, all
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    is_encrypted: Optional[bool] = None
    limit: Optional[int] = 50
    offset: Optional[int] = 0

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