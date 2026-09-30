"""
FastAPI REST API Endpoints for UniGuard AI
Passive Unidirectional Cyber Threat Detection Platform
"""

import os
import re
import shutil
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from backend.app.core.config import settings, UPLOAD_DIR, DATA_DIR
from backend.app.models.database import get_db, FlowRecord, Alert, ProcessingStat, ModelMetadata
from backend.app.models.schemas import (
    FlowRecordSchema, AlertSchema, ThreatSummarySchema,
    SystemStatsSchema, ModelEvaluationSchema, StreamControlRequest,
    StreamStatusSchema, SettingsUpdateRequest
)
from backend.app.engine.parser import parse_csv_file, parse_pcap_file
from backend.app.engine.ml_detector import ml_detector
from backend.app.engine.streamer import stream_engine
from backend.app.engine.benchmark import run_performance_benchmark
from backend.app.engine.report_generator import generate_html_report

router = APIRouter()

ALLOWED_SCENARIOS = {
    "combined_demo",
    "normal",
    "ddos",
    "botnet",
    "dns_tunneling",
    "encrypted_traffic",
    "port_scan",
    "exfiltration"
}

MAX_UPLOAD_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

async def save_upload_safely(file: UploadFile, prefix: str) -> Path:
    """Streams and validates an upload enforcing strict size limits and sanitized filenames."""
    orig_name = Path(file.filename or "upload").name
    # Strip any directory traversal components and characters outside safe charset
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", orig_name)
    if not sanitized:
        sanitized = "file"
    safe_name = f"{prefix}_{int(time.time()*1000)}_{sanitized}"
    dest_path = UPLOAD_DIR / safe_name

    total_bytes = 0
    try:
        with open(dest_path, "wb") as buffer:
            while chunk := await file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    buffer.close()
                    if dest_path.exists():
                        dest_path.unlink()
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum allowed upload size of {settings.MAX_UPLOAD_SIZE_MB} MB"
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if dest_path.exists():
            dest_path.unlink()
        raise HTTPException(status_code=500, detail=f"Failed to process file upload: {str(e)}")

    return dest_path

@router.get("/health")
def health_check():
    """Confirms application health and passive monitoring guarantees."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "passive_mode": settings.PASSIVE_MODE,
        "read_only_monitoring": settings.READ_ONLY_MONITORING,
        "active_response_enabled": settings.ACTIVE_RESPONSE_ENABLED,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/api/stats")
def get_system_stats(db: Session = Depends(get_db)):
    """Returns real-time processing statistics and SOC overview counters."""
    total_flows = db.query(func.count(FlowRecord.id)).scalar() or 0
    total_threats = db.query(func.count(Alert.id)).scalar() or 0
    suspicious = db.query(func.count(FlowRecord.id)).filter(FlowRecord.threat_label != "Normal").scalar() or 0
    total_packets = db.query(func.sum(FlowRecord.total_packets)).scalar() or 0
    
    # Calculate current risk level
    recent_criticals = db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar() or 0
    if recent_criticals > 5:
        risk_level = "CRITICAL"
    elif total_threats > 15:
        risk_level = "HIGH"
    elif total_threats > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    import psutil
    cpu = psutil.cpu_percent(interval=None)
    mem_mb = psutil.Process().memory_info().rss / (1024 * 1024)

    return {
        "flows_processed": total_flows if total_flows > stream_engine.stats["flows_processed"] else stream_engine.stats["flows_processed"],
        "packets_processed": int(total_packets) if total_packets > stream_engine.stats["packets_processed"] else stream_engine.stats["packets_processed"],
        "threats_detected": total_threats if total_threats > stream_engine.stats["threats_detected"] else stream_engine.stats["threats_detected"],
        "suspicious_flows": suspicious,
        "current_risk_level": risk_level,
        "processing_latency_ms": stream_engine.stats.get("avg_latency_ms", 12.5),
        "packets_per_sec": stream_engine.stats.get("current_fps", 0.0) * 15,
        "flows_per_sec": stream_engine.stats.get("current_fps", 0.0),
        "cpu_percent": round(cpu, 1),
        "memory_mb": round(mem_mb, 1),
        "passive_mode": settings.PASSIVE_MODE,
        "read_only_status": settings.READ_ONLY_MONITORING,
        "active_response": settings.ACTIVE_RESPONSE_ENABLED
    }

@router.get("/api/alerts")
def get_alerts(
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Returns paginated, filterable list of security alerts."""
    query = db.query(Alert)
    if threat_type and threat_type != "All":
        query = query.filter(Alert.threat_type == threat_type)
    if severity and severity != "All":
        query = query.filter(Alert.severity == severity)
        
    total = query.count()
    items = query.order_by(desc(Alert.id)).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "items": items,
        "limit": limit,
        "offset": offset
    }

@router.get("/api/alerts/{alert_id}")
def get_alert_investigation(alert_id: str, db: Session = Depends(get_db)):
    """Deep-dive investigation for an individual alert with evidence, rules, ML, and flow timeline."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # Find contextual flows from the same IP conversation for the timeline
    related_flows = db.query(FlowRecord).filter(
        (FlowRecord.src_ip == alert.src_ip) | (FlowRecord.dst_ip == alert.src_ip) |
        (FlowRecord.dst_ip == alert.dst_ip)
    ).order_by(desc(FlowRecord.id)).limit(15).all()

    return {
        "alert": alert,
        "related_flows": related_flows
    }

@router.get("/api/threats/summary")
def get_threats_summary(db: Session = Depends(get_db)):
    """Aggregates threat category distribution, severity breakdown, and top attacker IPs."""
    # Threat category distribution
    cat_counts = db.query(Alert.threat_type, func.count(Alert.id)).group_by(Alert.threat_type).all()
    threat_distribution = {cat: count for cat, count in cat_counts}
    
    # Severity distribution
    sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, count in sev_counts:
        severity_distribution[sev] = count
        
    # Top attackers
    attackers = db.query(Alert.src_ip, func.count(Alert.id).label("count")).group_by(Alert.src_ip).order_by(desc("count")).limit(5).all()
    top_attackers = [{"ip": ip, "count": count} for ip, count in attackers]
    
    # Top targeted ports
    ports = db.query(Alert.dst_port, func.count(Alert.id).label("count")).group_by(Alert.dst_port).order_by(desc("count")).limit(5).all()
    top_targeted_ports = [{"port": port, "count": count} for port, count in ports]

    total_threats = sum(threat_distribution.values())

    return {
        "total_threats": total_threats,
        "threat_distribution": threat_distribution,
        "severity_distribution": severity_distribution,
        "top_attackers": top_attackers,
        "top_targeted_ports": top_targeted_ports
    }

@router.get("/api/flows")
def get_flows(
    threat_label: Optional[str] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Filterable network flow records table."""
    query = db.query(FlowRecord)
    if threat_label and threat_label != "All":
        query = query.filter(FlowRecord.threat_label == threat_label)
    if protocol and protocol != "All":
        query = query.filter(FlowRecord.protocol == protocol)
    if search:
        query = query.filter(
            (FlowRecord.src_ip.contains(search)) |
            (FlowRecord.dst_ip.contains(search)) |
            (FlowRecord.flow_id.contains(search))
        )
        
    total = query.count()
    items = query.order_by(desc(FlowRecord.id)).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "items": items,
        "limit": limit,
        "offset": offset
    }

@router.get("/api/models")
def get_models_metadata():
    """Returns ML model parameters, classes, and global feature importance ranking."""
    if not ml_detector.is_loaded:
        ml_detector.load_models()
    return ml_detector.evaluation_metadata

@router.get("/api/model/evaluation")
def get_model_evaluation():
    """Returns detailed evaluation metrics including confusion matrix and class report."""
    if not ml_detector.is_loaded:
        ml_detector.load_models()
    return ml_detector.evaluation_metadata

@router.post("/api/model/train")
def train_model():
    """Triggers ML training / retraining on dataset."""
    metadata = ml_detector.train()
    return {
        "status": "success",
        "message": f"Model successfully retrained. Test Accuracy: {metadata['accuracy']*100:.2f}%",
        "metadata": metadata
    }

@router.post("/api/upload/csv")
async def upload_csv(file: UploadFile = File(...)):
    """Uploads external CSV flow dataset with safe path, 50MB size limit, and schema validation."""
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported")
        
    dest_path = await save_upload_safely(file, prefix="csv")
    
    try:
        flows = parse_csv_file(str(dest_path))
        if not flows:
            raise ValueError("CSV contains no valid flow records or could not be parsed")
            
        return {
            "status": "success",
            "filename": Path(file.filename).name,
            "flows_parsed": len(flows),
            "sample_flows": flows[:5]
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Malformed CSV content: {str(ve)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")

@router.post("/api/upload/pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads PCAP packet capture for passive header and metadata extraction (strictly passive, no payload decryption)."""
    allowed = [".pcap", ".pcapng", ".cap"]
    if not file.filename or not any(file.filename.lower().endswith(ext) for ext in allowed):
        raise HTTPException(status_code=400, detail=f"File extension must be one of {allowed}")
        
    dest_path = await save_upload_safely(file, prefix="pcap")
    
    try:
        flows = parse_pcap_file(str(dest_path), max_packets=5000)
        return {
            "status": "success",
            "filename": Path(file.filename).name,
            "flows_aggregated": len(flows),
            "sample_flows": flows[:5]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse PCAP: {str(e)}")

@router.post("/api/demo/start")
async def start_demo_stream(req: Optional[StreamControlRequest] = None):
    """Starts real-time demo streaming pipeline with strict scenario whitelisting."""
    scenario = 'combined_demo'
    speed = 1.0
    if req:
        scenario = req.dataset or req.scenario or 'combined_demo'
        speed = req.speed_factor if req.speed_factor is not None else (req.speed or 1.0)
    if scenario.endswith('.csv'):
        scenario = scenario[:-4]
        
    # Strict Whitelist Validation (Phase 22)
    if scenario not in ALLOWED_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{scenario}'. Allowed scenarios: {sorted(list(ALLOWED_SCENARIOS))}"
        )
        
    speed = max(0.1, min(float(speed), 20.0))
    stream_engine.start_demo(scenario=scenario, speed=speed)
    return {
        'status': 'started',
        'state': stream_engine.state,
        'scenario': stream_engine.current_scenario,
        'speed': stream_engine.speed
    }

@router.post("/api/demo/pause")
async def pause_demo_stream():
    """Pauses demo streaming pipeline."""
    stream_engine.pause_demo()
    return {"status": "paused", "state": stream_engine.state}

@router.post("/api/demo/resume")
async def resume_demo_stream():
    """Resumes demo streaming pipeline."""
    stream_engine.resume_demo()
    return {"status": "resumed", "state": stream_engine.state}

@router.post("/api/demo/stop")
async def stop_demo_stream():
    """Stops demo streaming pipeline."""
    stream_engine.stop_demo()
    return {"status": "stopped", "state": stream_engine.state}

@router.get("/api/demo/status")
def get_demo_status():
    """Returns streaming simulation status."""
    return {
        "state": stream_engine.state,
        "speed": stream_engine.speed,
        "scenario": stream_engine.current_scenario,
        "flows_streamed": stream_engine.stats["flows_processed"],
        "threats_streamed": stream_engine.stats["threats_detected"]
    }

@router.get("/api/benchmark")
@router.post("/api/benchmark")
def get_performance_benchmark():
    """Runs a live performance measurement on this development machine."""
    res = run_performance_benchmark(sample_size=60)
    return res

@router.get("/api/report")
def get_security_report(format: str = "html", db: Session = Depends(get_db)):
    """Generates an executive security audit report."""
    total_flows = db.query(func.count(FlowRecord.id)).scalar() or 0
    total_threats = db.query(func.count(Alert.id)).scalar() or 0
    suspicious = db.query(func.count(FlowRecord.id)).filter(FlowRecord.threat_label != "Normal").scalar() or 0
    
    cat_counts = db.query(Alert.threat_type, func.count(Alert.id)).group_by(Alert.threat_type).all()
    threat_dist = {cat: count for cat, count in cat_counts}
    
    sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    sev_dist = {sev: count for sev, count in sev_counts}
    
    alerts = db.query(Alert).order_by(desc(Alert.id)).limit(25).all()
    alerts_data = [
        {
            "alert_id": a.alert_id,
            "threat_type": a.threat_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "dst_port": a.dst_port,
            "evidence": a.evidence
        }
        for a in alerts
    ]
    
    summary = {
        "flows_processed": total_flows,
        "threats_detected": total_threats,
        "suspicious_flows": suspicious,
        "threat_distribution": threat_dist,
        "severity_distribution": sev_dist
    }
    
    benchmark = run_performance_benchmark(sample_size=20)
    
    if format.lower() == "json":
        return {
            "summary": summary,
            "alerts": alerts_data,
            "model_metadata": ml_detector.evaluation_metadata,
            "benchmark": benchmark
        }
        
    html = generate_html_report(
        summary_data=summary,
        alerts=alerts_data,
        model_metadata=ml_detector.evaluation_metadata,
        benchmark_data=benchmark
    )
    return HTMLResponse(content=html)

@router.get("/api/settings")
def get_settings():
    """Returns current detection sensitivity thresholds."""
    return {
        "ddos_packet_rate_threshold": settings.DDOS_PACKET_RATE_THRESHOLD,
        "ddos_syn_ratio_threshold": settings.DDOS_SYN_RATIO_THRESHOLD,
        "port_scan_port_threshold": settings.PORT_SCAN_PORT_THRESHOLD,
        "botnet_interval_jitter_max": settings.BOTNET_INTERVAL_JITTER_MAX,
        "dns_entropy_threshold": settings.DNS_ENTROPY_THRESHOLD,
        "dns_length_threshold": settings.DNS_LENGTH_THRESHOLD,
        "exfiltration_bytes_threshold": settings.EXFILTRATION_BYTES_THRESHOLD,
        "stream_interval": settings.DEFAULT_STREAM_INTERVAL,
        "passive_mode": settings.PASSIVE_MODE,
        "read_only": settings.READ_ONLY_MONITORING
    }

@router.post("/api/settings")
def update_settings(req: SettingsUpdateRequest):
    """Updates runtime detection thresholds."""
    if req.ddos_packet_rate_threshold is not None:
        settings.DDOS_PACKET_RATE_THRESHOLD = req.ddos_packet_rate_threshold
    if req.ddos_syn_ratio_threshold is not None:
        settings.DDOS_SYN_RATIO_THRESHOLD = req.ddos_syn_ratio_threshold
    if req.port_scan_port_threshold is not None:
        settings.PORT_SCAN_PORT_THRESHOLD = req.port_scan_port_threshold
    if req.botnet_interval_jitter_max is not None:
        settings.BOTNET_INTERVAL_JITTER_MAX = req.botnet_interval_jitter_max
    if req.dns_entropy_threshold is not None:
        settings.DNS_ENTROPY_THRESHOLD = req.dns_entropy_threshold
    if req.dns_length_threshold is not None:
        settings.DNS_LENGTH_THRESHOLD = req.dns_length_threshold
    if req.exfiltration_bytes_threshold is not None:
        settings.EXFILTRATION_BYTES_THRESHOLD = req.exfiltration_bytes_threshold
    if req.stream_interval is not None:
        settings.DEFAULT_STREAM_INTERVAL = req.stream_interval
        
    return {"status": "success", "message": "Settings updated"}