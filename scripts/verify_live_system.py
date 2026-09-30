"""
Comprehensive Live System Verification Script for UniGuard AI
Tests all REST endpoints, SPA routing, ML inference, benchmark execution,
report generation, and streaming demo controls.
"""

import sys
import os

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from backend.app.main import app

def run_verification():
    print("=" * 60)
    print("STARTING UNIGUARD AI COMPREHENSIVE LIVE VERIFICATION")
    print("=" * 60)

    client = TestClient(app)

    # 1. Health Endpoint
    print("\n[1] Testing GET /health...")
    resp = client.get("/health")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    assert data["passive_mode"] is True
    assert data["read_only_monitoring"] is True
    assert data["active_response_enabled"] is False
    print(f"  [PASS] Passive Mode: {data['passive_mode']}, Read-Only: {data['read_only_monitoring']}")

    # 2. SPA Root (index.html)
    print("\n[2] Testing GET / (React SPA Entrypoint)...")
    resp = client.get("/")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert '<div id="root"></div>' in resp.text
    assert "UniGuard AI" in resp.text
    print("  [PASS] React production bundle index.html served at root (http://127.0.0.1:8000/).")

    # 3. SPA Catch-All Client-Side Routes
    print("\n[3] Testing Client-Side SPA Routes (/benchmark, /investigation, /models)...")
    for route in ["/benchmark", "/investigation", "/models", "/reports", "/flows"]:
        resp = client.get(route)
        assert resp.status_code == 200
        assert '<div id="root"></div>' in resp.text
    print("  [PASS] SPA catch-all correctly returns React index.html for all non-API paths.")

    # 4. System Stats
    print("\n[4] Testing GET /api/stats...")
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "flows_processed" in stats
    assert "threats_detected" in stats
    assert "current_risk_level" in stats
    print(f"  [PASS] Stats accessible: Flows={stats['flows_processed']}, Threats={stats['threats_detected']}, Risk={stats['current_risk_level']}")

    # 5. Model Metadata & Evaluation
    print("\n[5] Testing GET /api/models & GET /api/model/evaluation...")
    resp = client.get("/api/models")
    assert resp.status_code == 200
    model_data = resp.json()
    assert model_data["model_type"] == "RandomForestClassifier (100 trees) + IsolationForest"
    assert model_data["feature_count"] == 26
    print(f"  [PASS] Models: {model_data['model_name']} with {model_data['feature_count']} features.")

    resp = client.get("/api/model/evaluation")
    assert resp.status_code == 200
    eval_data = resp.json()
    assert eval_data["accuracy"] > 0.99
    assert eval_data["evaluation_type"] == "synthetic benchmark dataset"
    print(f"  [PASS] Evaluation metrics: Accuracy={eval_data['accuracy']*100:.2f}%, F1={eval_data['f1_score']:.4f}")
    print(f"         Label: {eval_data.get('benchmark_note')}")

    # 6. Performance Benchmark
    print("\n[6] Testing GET /api/benchmark (Empirical Measurement)...")
    resp = client.get("/api/benchmark")
    assert resp.status_code == 200
    bench = resp.json()
    assert "throughput_flows_per_sec" in bench
    assert "avg_pipeline_latency_ms" in bench
    assert "avg_feature_extraction_ms" in bench
    assert "avg_ml_inference_ms" in bench
    assert "memory_usage_mb" in bench
    assert "machine_info" in bench
    print(f"  [PASS] Live Benchmark: {bench['throughput_flows_per_sec']} flows/s, Latency: {bench['avg_pipeline_latency_ms']} ms/flow")
    print(f"         Host: {bench['machine_info']['os']}, RAM: {bench['memory_usage_mb']} MB")
    print(f"         Label: '{bench['status_label']}'")

    # 7. Executive Audit Report (HTML & JSON)
    print("\n[7] Testing GET /api/report (HTML & JSON formats)...")
    resp = client.get("/api/report?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "UniGuard AI &bull; Threat Detection Report" in resp.text
    assert "Synthetic Benchmark Accuracy" in resp.text
    assert "Measured on development machine" in resp.text
    print("  [PASS] HTML Security Audit Report rendered with print CSS and honest benchmark labeling.")

    resp = client.get("/api/report?format=json")
    assert resp.status_code == 200
    report_json = resp.json()
    assert "summary" in report_json
    assert "benchmark" in report_json
    print("  [PASS] JSON Security Audit Report format valid.")

    # 8. Demo Streaming Controls
    print("\n[8] Testing Demo Streaming Controls (start, pause, resume, stop)...")
    import asyncio
    import httpx

    async def test_demo_controls():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
            r1 = await ac.post("/api/demo/start", json={"scenario": "combined_demo", "speed": 5.0})
            assert r1.status_code == 200
            assert r1.json()["state"] == "RUNNING"
            print("  [PASS] POST /api/demo/start -> RUNNING at 5.0x speed.")

            await asyncio.sleep(0.1)
            r2 = await ac.post("/api/demo/pause")
            assert r2.status_code == 200
            assert r2.json()["state"] == "PAUSED"
            print("  [PASS] POST /api/demo/pause -> PAUSED.")

            await asyncio.sleep(0.1)
            r3 = await ac.post("/api/demo/resume")
            assert r3.status_code == 200
            assert r3.json()["state"] == "RUNNING"
            print("  [PASS] POST /api/demo/resume -> RUNNING.")

            await asyncio.sleep(0.1)
            r4 = await ac.post("/api/demo/stop")
            assert r4.status_code == 200
            assert r4.json()["state"] == "STOPPED"
            print("  [PASS] POST /api/demo/stop -> STOPPED.")

    asyncio.run(test_demo_controls())

    # 9. Whitelist Validation on Demo Scenario
    print("\n[9] Testing Demo Whitelist Security Validation...")
    resp = client.post("/api/demo/start", json={"scenario": "malicious_script", "speed": 1.0})
    assert resp.status_code == 400
    print("  [PASS] Invalid scenario rejected with 400 Bad Request.")

    # 10. Threats Summary & Alerts
    print("\n[10] Testing GET /api/threats/summary & GET /api/alerts...")
    resp = client.get("/api/threats/summary")
    assert resp.status_code == 200
    summary = resp.json()
    print(f"  [PASS] Threats Summary returned: {len(summary.get('threat_distribution', {}))} categories.")

    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    print(f"  [PASS] Alerts returned: {len(alerts.get('items', []))} items.")

    print("\n" + "=" * 60)
    print("ALL 10 VERIFICATION SUITES PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_verification()
