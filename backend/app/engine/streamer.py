"""
Real-Time Asynchronous Streaming & Replay Engine
Streams flow events incrementally, passes each flow through the full detection pipeline,
persists records to SQLite, and broadcasts real-time telemetry over WebSockets.
Supports Start, Pause, Resume, Stop, and variable playback speeds (0.5x - 10x).
"""

import asyncio
import json
import time
import pandas as pd
from typing import Dict, Any, List, Set, Optional
from datetime import datetime
from starlette.websockets import WebSocket

from backend.app.core.config import DATA_DIR, settings
from backend.app.models.database import SessionLocal, FlowRecord, Alert, ProcessingStat, ThreatEvent
from backend.app.engine.feature_extractor import extract_flow_features
from backend.app.engine.rules import RuleEngine
from backend.app.engine.ml_detector import ml_detector
from backend.app.engine.correlator import threat_correlator

class StreamingEngine:
    def __init__(self):
        self.state: str = "STOPPED"  # STOPPED, RUNNING, PAUSED
        self.speed: float = 1.0
        self.current_scenario: str = "combined_demo"
        self.active_connections: Set[WebSocket] = set()
        
        self.worker_task: Optional[asyncio.Task] = None
        self.rule_engine = RuleEngine()
        
        self.total_flows_streamed = 0
        self.total_threats_streamed = 0
        self.start_time: Optional[float] = None
        
        self.stats = {
            "flows_processed": 0,
            "packets_processed": 0,
            "threats_detected": 0,
            "suspicious_flows": 0,
            "current_fps": 0.0,
            "avg_latency_ms": 0.0,
            "current_risk_level": "LOW",
            "cpu_percent": 0.0,
            "memory_mb": 0.0
        }

    async def connect_client(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send initial status
        await websocket.send_json({
            "type": "init_status",
            "state": self.state,
            "speed": self.speed,
            "scenario": self.current_scenario,
            "stats": self.stats
        })

    def disconnect_client(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_connections.discard(ws)

    def start_demo(self, scenario: str = "combined_demo", speed: float = 1.0):
        if self.state == "RUNNING":
            self.stop_demo()
            
        self.state = "RUNNING"
        self.speed = max(0.1, min(speed, 20.0))
        self.current_scenario = scenario
        self.start_time = time.time()
        
        # Spawn async streaming worker in the running event loop
        try:
            loop = asyncio.get_running_loop()
            self.worker_task = loop.create_task(self._run_stream_worker())
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                self.worker_task = loop.create_task(self._run_stream_worker())
            except Exception as e:
                print(f"[!] Could not spawn async stream worker: {e}")
        print(f"[+] Started demo streaming: scenario={scenario}, speed={speed}x")

    def pause_demo(self):
        if self.state == "RUNNING":
            self.state = "PAUSED"
            print("[||] Demo stream paused.")

    def resume_demo(self):
        if self.state == "PAUSED":
            self.state = "RUNNING"
            print("[>] Demo stream resumed.")

    def stop_demo(self):
        self.state = "STOPPED"
        if self.worker_task and not self.worker_task.done():
            self.worker_task.cancel()
        self.worker_task = None
        print("[x] Demo stream stopped.")

    def set_speed(self, speed: float):
        self.speed = max(0.1, min(speed, 20.0))
        print(f"[*] Stream speed set to {self.speed}x")

    async def _run_stream_worker(self):
        csv_path = DATA_DIR / f"{self.current_scenario}.csv"
        if not csv_path.exists():
            csv_path = DATA_DIR / "combined_demo.csv"
            
        df = pd.read_csv(csv_path)
        records = df.to_dict(orient="records")
        idx = 0
        total_records = len(records)
        
        db = SessionLocal()
        
        try:
            while self.state in ["RUNNING", "PAUSED"]:
                if self.state == "PAUSED":
                    await asyncio.sleep(0.5)
                    continue
                    
                batch_size = max(1, int(settings.DEFAULT_BATCH_SIZE * (self.speed / 2.0)))
                batch_flows = []
                for _ in range(batch_size):
                    row = records[idx % total_records]
                    idx += 1
                    batch_flows.append(row)
                    
                t_batch_start = time.perf_counter()
                
                for raw_flow in batch_flows:
                    current_iso = datetime.utcnow()
                    raw_flow["ts_epoch"] = time.time()
                    
                    # 1. Feature Extraction
                    features = extract_flow_features(raw_flow, update_context=True)
                    
                    # 2. Multi-Signal Rules
                    rule_matches = self.rule_engine.evaluate_flow(raw_flow, features)
                    
                    # 3. Supervised ML & Unsupervised Anomaly
                    ml_result = ml_detector.predict(features)
                    
                    # 4. Threat Correlation & Risk Assessment
                    alert = threat_correlator.correlate(raw_flow, features, rule_matches, ml_result)
                    
                    # 5. Database Persistence
                    flow_rec = FlowRecord(
                        flow_id=raw_flow.get("flow_id", f"fl_{int(time.time()*1000)}"),
                        timestamp=current_iso,
                        src_ip=raw_flow.get("src_ip", "10.0.0.1"),
                        dst_ip=raw_flow.get("dst_ip", "10.0.0.2"),
                        src_port=int(raw_flow.get("src_port", 0)),
                        dst_port=int(raw_flow.get("dst_port", 0)),
                        protocol=raw_flow.get("protocol", "TCP"),
                        duration=float(raw_flow.get("duration", 0.0)),
                        total_bytes=int(raw_flow.get("total_bytes", 0)),
                        total_packets=int(raw_flow.get("total_packets", 0)),
                        packets_per_sec=float(features.get("packets_per_sec", 0.0)),
                        bytes_per_sec=float(features.get("bytes_per_sec", 0.0)),
                        tcp_flags=raw_flow.get("tcp_flags", ""),
                        dns_query=raw_flow.get("dns_query") if pd.notna(raw_flow.get("dns_query")) else None,
                        sni=raw_flow.get("sni") if pd.notna(raw_flow.get("sni")) else None,
                        is_encrypted=bool(raw_flow.get("protocol") == "TLS" or raw_flow.get("dst_port") in [443, 8443]),
                        threat_label=alert.threat_type if alert else "Normal",
                        risk_score=alert.risk_score if alert else 0.0
                    )
                    db.add(flow_rec)
                    
                    # Update local state stats
                    self.stats["flows_processed"] += 1
                    self.stats["packets_processed"] += int(raw_flow.get("total_packets", 1))
                    
                    alert_dict = None
                    if alert:
                        self.stats["threats_detected"] += 1
                        alert_rec = Alert(
                            alert_id=alert.alert_id,
                            timestamp=current_iso,
                            threat_type=alert.threat_type,
                            severity=alert.severity,
                            confidence=alert.confidence,
                            risk_score=alert.risk_score,
                            src_ip=alert.src_ip,
                            dst_ip=alert.dst_ip,
                            src_port=alert.src_port,
                            dst_port=alert.dst_port,
                            protocol=alert.protocol,
                            duration=alert.duration,
                            total_bytes=alert.total_bytes,
                            total_packets=alert.total_packets,
                            evidence=alert.evidence,
                            rule_matches=alert.rule_matches,
                            ml_prediction=alert.ml_prediction,
                            ml_confidence=alert.ml_confidence,
                            contributing_features=alert.contributing_features,
                            flow_id=alert.flow_id
                        )
                        db.add(alert_rec)
                        
                        alert_dict = {
                            "alert_id": alert.alert_id,
                            "timestamp": current_iso.isoformat(),
                            "threat_type": alert.threat_type,
                            "severity": alert.severity,
                            "confidence": alert.confidence,
                            "risk_score": alert.risk_score,
                            "src_ip": alert.src_ip,
                            "dst_ip": alert.dst_ip,
                            "src_port": alert.src_port,
                            "dst_port": alert.dst_port,
                            "protocol": alert.protocol,
                            "evidence": alert.evidence,
                            "contributing_features": alert.contributing_features
                        }
                    elif ml_result.get("is_anomaly", False):
                        self.stats["suspicious_flows"] += 1

                    # 6. WebSocket Real-Time Broadcast
                    flow_payload = {
                        "type": "flow_event",
                        "flow": {
                            "flow_id": flow_rec.flow_id,
                            "timestamp": current_iso.isoformat(),
                            "src_ip": flow_rec.src_ip,
                            "dst_ip": flow_rec.dst_ip,
                            "src_port": flow_rec.src_port,
                            "dst_port": flow_rec.dst_port,
                            "protocol": flow_rec.protocol,
                            "total_bytes": flow_rec.total_bytes,
                            "total_packets": flow_rec.total_packets,
                            "threat_label": flow_rec.threat_label,
                            "risk_score": flow_rec.risk_score
                        },
                        "alert": alert_dict
                    }
                    await self.broadcast(flow_payload)

                db.commit()
                
                # Update processing FPS and latency
                t_batch_elapsed = max(time.perf_counter() - t_batch_start, 0.001)
                self.stats["current_fps"] = round(batch_size / t_batch_elapsed, 1)
                self.stats["avg_latency_ms"] = round((t_batch_elapsed / batch_size) * 1000.0, 2)
                
                # Dynamic risk level based on recent threats
                if self.stats["threats_detected"] > 20:
                    self.stats["current_risk_level"] = "CRITICAL"
                elif self.stats["threats_detected"] > 10:
                    self.stats["current_risk_level"] = "HIGH"
                elif self.stats["threats_detected"] > 3:
                    self.stats["current_risk_level"] = "MEDIUM"
                else:
                    self.stats["current_risk_level"] = "LOW"
                    
                # Broadcast periodically updated stats
                await self.broadcast({
                    "type": "stats_update",
                    "stats": self.stats
                })
                
                # Adaptive sleep between simulation ticks
                base_sleep = settings.DEFAULT_STREAM_INTERVAL / self.speed
                await asyncio.sleep(max(base_sleep, 0.05))

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[!] Streaming worker error: {e}")
        finally:
            db.close()
            self.state = "STOPPED"

stream_engine = StreamingEngine()
