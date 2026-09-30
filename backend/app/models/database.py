"""
SQLAlchemy ORM Models for SQLite Storage
"""

import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.core.config import settings

Base = declarative_base()
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class FlowRecord(Base):
    __tablename__ = "flows"
    
    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String(64), index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, index=True)
    protocol = Column(String(10), index=True)  # TCP, UDP, ICMP, DNS, TLS
    duration = Column(Float, default=0.0)
    total_bytes = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    packets_per_sec = Column(Float, default=0.0)
    bytes_per_sec = Column(Float, default=0.0)
    tcp_flags = Column(String(32), default="")
    dns_query = Column(String(255), nullable=True)
    sni = Column(String(255), nullable=True)
    is_encrypted = Column(Boolean, default=False)
    threat_label = Column(String(50), default="Normal", index=True)
    risk_score = Column(Float, default=0.0)
    features_json = Column(Text, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    threat_type = Column(String(50), index=True)  # DDoS, Botnet C2, DGA/DNS Tunneling, Suspicious Encrypted, Port Scan, Data Exfiltration
    severity = Column(String(20), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    duration = Column(Float, default=0.0)
    total_bytes = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    evidence = Column(JSON, default=list)
    rule_matches = Column(JSON, default=list)
    ml_prediction = Column(String(50), default="")
    ml_confidence = Column(Float, default=0.0)
    contributing_features = Column(JSON, default=list)
    flow_id = Column(String(64), index=True)
    acknowledged = Column(Boolean, default=False)

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    threat_type = Column(String(50), index=True)
    severity = Column(String(20))
    count = Column(Integer, default=1)
    source_ip = Column(String(45))

class ProcessingStat(Base):
    __tablename__ = "processing_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    flows_processed = Column(Integer, default=0)
    packets_processed = Column(Integer, default=0)
    bytes_processed = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    suspicious_flows = Column(Integer, default=0)
    current_fps = Column(Float, default=0.0)
    avg_latency_ms = Column(Float, default=0.0)
    cpu_percent = Column(Float, default=0.0)
    memory_mb = Column(Float, default=0.0)

class ModelMetadata(Base):
    __tablename__ = "model_metadata"
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), default="UniGuard-RF-Detector")
    model_type = Column(String(50), default="RandomForestClassifier + IsolationForest")
    version = Column(String(20), default="1.0.0")
    training_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    dataset_name = Column(String(100), default="UniGuard Unidirectional Flow Benchmark")
    feature_count = Column(Integer, default=26)
    feature_names = Column(JSON, default=list)
    classes = Column(JSON, default=list)
    accuracy = Column(Float, default=0.0)
    precision = Column(Float, default=0.0)
    recall = Column(Float, default=0.0)
    f1_score = Column(Float, default=0.0)
    confusion_matrix = Column(JSON, default=list)
    classification_report = Column(JSON, default=dict)
    false_positive_rate = Column(Float, default=0.0)
    false_negative_rate = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)
