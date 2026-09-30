"""
Real Performance Benchmark Runner
Executes actual timing tests on the local machine to measure
feature extraction latency, ML inference latency, rule evaluation latency,
end-to-end throughput (flows/sec), and resource utilization.
Never fabricates or hardcodes benchmark numbers.
"""

import time
import platform
import psutil
import numpy as np
from typing import Dict, Any, List

from backend.app.generator.traffic_generator import generate_normal_flows, generate_ddos_flows
from backend.app.engine.feature_extractor import extract_flow_features
from backend.app.engine.rules import RuleEngine
from backend.app.engine.ml_detector import ml_detector
from backend.app.engine.correlator import threat_correlator

def run_performance_benchmark(sample_size: int = 60) -> Dict[str, Any]:
    """
    Measures real execution latencies on current system hardware.
    """
    print(f"[*] Starting live hardware benchmark with {sample_size} flow samples...")
    
    # 1. Generate test flows
    test_flows = generate_normal_flows(count=sample_size // 2) + generate_ddos_flows(count=sample_size // 2)
    rule_engine = RuleEngine()
    
    # Measure Feature Extraction Latency
    feature_times = []
    extracted_features = []
    for flow in test_flows:
        t0 = time.perf_counter()
        feats = extract_flow_features(flow, update_context=False)
        t1 = time.perf_counter()
        feature_times.append((t1 - t0) * 1000.0)  # to ms
        extracted_features.append(feats)
        
    avg_feat_latency = float(np.mean(feature_times))
    p95_feat_latency = float(np.percentile(feature_times, 95))
    
    # Measure Rule Evaluation Latency
    rule_times = []
    rule_results = []
    for flow, feats in zip(test_flows, extracted_features):
        t0 = time.perf_counter()
        matches = rule_engine.evaluate_flow(flow, feats)
        t1 = time.perf_counter()
        rule_times.append((t1 - t0) * 1000.0)
        rule_results.append(matches)
        
    avg_rule_latency = float(np.mean(rule_times))
    
    # Measure ML Inference Latency
    ml_times = []
    ml_results = []
    for feats in extracted_features:
        t0 = time.perf_counter()
        res = ml_detector.predict(feats)
        t1 = time.perf_counter()
        ml_times.append((t1 - t0) * 1000.0)
        ml_results.append(res)
        
    avg_ml_latency = float(np.mean(ml_times))
    p95_ml_latency = float(np.percentile(ml_times, 95))
    
    # Measure Full End-to-End Pipeline Throughput
    t_start = time.perf_counter()
    alerts_count = 0
    for flow, feats, matches, ml_res in zip(test_flows, extracted_features, rule_results, ml_results):
        alert = threat_correlator.correlate(flow, feats, matches, ml_res)
        if alert:
            alerts_count += 1
    t_total = time.perf_counter() - t_start
    
    flows_per_sec = float(sample_size / max(t_total + sum(feature_times)/1000 + sum(ml_times)/1000, 0.001))
    avg_pipeline_latency = float(avg_feat_latency + avg_rule_latency + avg_ml_latency + (t_total/sample_size)*1000)
    
    # System Resource Metrics
    process = psutil.Process()
    mem_info = process.memory_info()
    memory_mb = float(mem_info.rss / (1024 * 1024))
    cpu_percent = float(psutil.cpu_percent(interval=0.05))
    
    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "machine_info": {
            "os": f"{platform.system()} {platform.release()}",
            "processor": platform.processor() or "x86_64",
            "cpu_cores": psutil.cpu_count(logical=True),
            "python_version": platform.python_version()
        },
        "sample_size": sample_size,
        "throughput_flows_per_sec": round(flows_per_sec, 1),
        "avg_pipeline_latency_ms": round(avg_pipeline_latency, 3),
        "avg_feature_extraction_ms": round(avg_feat_latency, 3),
        "p95_feature_extraction_ms": round(p95_feat_latency, 3),
        "avg_ml_inference_ms": round(avg_ml_latency, 3),
        "p95_ml_inference_ms": round(p95_ml_latency, 3),
        "avg_rule_evaluation_ms": round(avg_rule_latency, 3),
        "memory_usage_mb": round(memory_mb, 1),
        "cpu_usage_percent": round(cpu_percent, 1),
        "alerts_generated": alerts_count,
        "status_label": "Measured on this development machine."
    }
    
    print(f"[?] Benchmark completed: {flows_per_sec:.1f} flows/sec, {avg_pipeline_latency:.3f} ms/flow")
    return result

if __name__ == "__main__":
    import json
    res = run_performance_benchmark(60)
    print(json.dumps(res, indent=2))
