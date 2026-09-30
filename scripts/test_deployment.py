import os
import sys
import time

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi.testclient import TestClient
from backend.app.main import app

def test_full_deployment_stack():
    print("[*] Running UniGuard AI Deployment Verification...")
    with TestClient(app) as client:
        # 1. Test Root / SPA index.html
        res = client.get("/")
        assert res.status_code == 200, f"Root returned {res.status_code}"
        print("  [x] Root SPA (GET /): OK (status 200)")

        # 2. Test Health / Stats API
        res = client.get("/api/stats")
        assert res.status_code == 200, f"Stats returned {res.status_code}"
        stats = res.json()
        assert "flows_processed" in stats
        print(f"  [x] Stats API (GET /api/stats): OK (flows: {stats['flows_processed']})")

        # 3. Test Threats Summary
        res = client.get("/api/threats/summary")
        assert res.status_code == 200
        print("  [x] Threats Summary (GET /api/threats/summary): OK")

        # 4. Test Model Evaluation
        res = client.get("/api/model/evaluation")
        assert res.status_code == 200
        print("  [x] Model Evaluation (GET /api/model/evaluation): OK")

        # 5. Test Demo Start & Stop
        res = client.post("/api/demo/start", json={"scenario": "combined_demo", "speed": 2.0})
        assert res.status_code == 200
        print("  [x] Demo Stream (POST /api/demo/start): OK")
        time.sleep(1.5)
        res = client.post("/api/demo/stop")
        assert res.status_code == 200
        print("  [x] Demo Stop (POST /api/demo/stop): OK")

        # 6. Test Alerts
        res = client.get("/api/alerts?limit=10")
        assert res.status_code == 200
        alerts = res.json()
        print(f"  [x] Alerts Query (GET /api/alerts): OK (total: {alerts['total']})")

        # 7. Test Assets
        res = client.get("/api/assets")
        assert res.status_code == 200
        print("  [x] Asset Inventory (GET /api/assets): OK")

        # 8. Test Cases
        res = client.get("/api/cases")
        assert res.status_code == 200
        print("  [x] Case Management (GET /api/cases): OK")

        # 9. Test Threat Intel
        res = client.get("/api/threat-intel")
        assert res.status_code == 200
        print("  [x] Threat Intel (GET /api/threat-intel): OK")

        # 10. Test WebSocket alerts endpoint
        with client.websocket_connect("/ws/alerts") as websocket:
            print("  [x] WebSocket Alerts (/ws/alerts): Handshake OK, Connected successfully")

    print("[SUCCESS] All 10 deployment verification checks passed!")

if __name__ == "__main__":
    test_full_deployment_stack()
