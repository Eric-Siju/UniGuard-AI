import asyncio
import json
import urllib.request
import urllib.error
import ssl
import websockets
import time

BACKEND_BASE = "https://uniguard-ai-ntw4.onrender.com"
FRONTEND_URL = "https://uniguard-ai-sih.vercel.app"
WS_URL = "wss://uniguard-ai-ntw4.onrender.com/ws/alerts"

results = {}

def log_test(name, passed, detail=""):
    results[name] = "PASS" if passed else "FAIL"
    status_str = "[PASS]" if passed else "[FAIL]"
    print(f"{status_str} {name}: {detail}")

def http_get(url, origin=None):
    headers = {"User-Agent": "UniGuard-Verifier/1.0"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")

def http_post(url, data=None, origin=None):
    headers = {
        "User-Agent": "UniGuard-Verifier/1.0",
        "Content-Type": "application/json"
    }
    if origin:
        headers["Origin"] = origin
    body = json.dumps(data).encode("utf-8") if data else b"{}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")

async def test_full_pipeline():
    print("=" * 60)
    print("STARTING END-TO-END VERIFICATION")
    print(f"Target Frontend: {FRONTEND_URL}")
    print(f"Target Backend:  {BACKEND_BASE}")
    print("=" * 60)

    # 1. Test Vercel Site
    try:
        status, headers, body = http_get(FRONTEND_URL)
        has_title = "<title>UniGuard AI" in body
        has_bundle = "/assets/index-" in body
        vercel_pass = (status == 200 and has_title and has_bundle)
        log_test("Vercel", vercel_pass, f"HTTP {status}, Title & SPA bundle delivered")
    except Exception as e:
        log_test("Vercel", False, str(e))

    # 2. Test Render Backend Reachability
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/health")
        data = json.loads(body)
        render_pass = (status == 200 and data.get("status") == "healthy")
        log_test("Render", render_pass, f"HTTP {status}, service healthy: {data.get('app_name')}")
    except Exception as e:
        log_test("Render", False, str(e))

    # 3. Test Health API
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/health")
        data = json.loads(body)
        health_pass = (data.get("passive_mode") is True and data.get("read_only_monitoring") is True)
        log_test("Health API", health_pass, f"Version: {data.get('version')}, Passive: {data.get('passive_mode')}")
    except Exception as e:
        log_test("Health API", False, str(e))

    # 4. Test GET /api/stats
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/api/stats")
        data = json.loads(body)
        stats_pass = (status == 200 and "flows_processed" in data)
        print(f"  -> Stats: flows_processed={data.get('flows_processed')}, risk_level={data.get('risk_level')}")
    except Exception as e:
        print(f"  -> Stats error: {e}")

    # 5. Test GET /api/alerts
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/api/alerts?limit=5")
        data = json.loads(body)
        print(f"  -> Alerts: total={data.get('total')}, returned={len(data.get('items', []))}")
    except Exception as e:
        print(f"  -> Alerts error: {e}")

    # 6. Test GET /api/threats/summary
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/api/threats/summary")
        data = json.loads(body)
        print(f"  -> Threat Summary: total_threats={data.get('total_threats')}, critical={data.get('critical_count')}")
    except Exception as e:
        print(f"  -> Threat Summary error: {e}")

    # 7. Test GET /api/model/evaluation
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/api/model/evaluation")
        data = json.loads(body)
        print(f"  -> Model Evaluation: accuracy={data.get('accuracy')}, f1={data.get('f1_macro')}")
    except Exception as e:
        print(f"  -> Model Evaluation error: {e}")

    # 8. Test Demo Start
    try:
        status, headers, body = http_post(
            f"{BACKEND_BASE}/api/demo/start",
            {"scenario": "combined_demo", "speed": 2.0},
            origin=FRONTEND_URL
        )
        data = json.loads(body)
        cors_origin = headers.get("Access-Control-Allow-Origin")
        demo_start_pass = (status == 200 and data.get("status") == "started")
        log_test("Demo Start", demo_start_pass, f"HTTP {status}, state={data.get('state')}, CORS={cors_origin}")
    except Exception as e:
        log_test("Demo Start", False, str(e))

    # 9. Test WebSocket Connection and Live Streaming
    ws_pass = False
    live_traffic_pass = False
    live_alerts_pass = False

    try:
        print(f"Connecting to WebSocket: {WS_URL} ...")
        ssl_ctx = ssl.create_default_context()
        async with websockets.connect(WS_URL, ssl=ssl_ctx) as ws:
            ws_pass = True
            log_test("WebSocket", True, "Handshake successful (WSS 101 Switching Protocols)")

            events_received = []
            timeout_at = time.time() + 15
            while time.time() < timeout_at and len(events_received) < 10:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    evt = json.loads(msg)
                    events_received.append(evt)
                    evt_type = evt.get("type")
                    if evt_type == "flow_event":
                        live_traffic_pass = True
                    if evt_type in ("alert_event", "new_alert") or (evt_type == "flow_event" and evt.get("data", {}).get("is_threat")):
                        live_alerts_pass = True
                except asyncio.TimeoutError:
                    break

            print(f"  -> Received {len(events_received)} live WebSocket messages.")
            for i, evt in enumerate(events_received[:5]):
                print(f"     [{i+1}] type={evt.get('type')}")
    except Exception as e:
        log_test("WebSocket", False, str(e))

    # Also verify live traffic and alerts from REST stats if needed
    try:
        status, headers, body = http_get(f"{BACKEND_BASE}/api/stats")
        data = json.loads(body)
        if data.get("flows_processed", 0) > 0:
            live_traffic_pass = True
        if data.get("threats_detected", 0) > 0:
            live_alerts_pass = True
    except:
        pass

    log_test("Live Traffic", live_traffic_pass, "Real-time flow events observed over WSS / stats")
    log_test("Live Alerts", live_alerts_pass, "Threat detections and alerts processed")

    # 10. Test Demo Pause
    try:
        status, headers, body = http_post(f"{BACKEND_BASE}/api/demo/pause", origin=FRONTEND_URL)
        data = json.loads(body)
        pause_pass = (status == 200 and data.get("status") == "paused")
        log_test("Pause", pause_pass, f"HTTP {status}, state={data.get('state')}")
    except Exception as e:
        log_test("Pause", False, str(e))

    # 11. Test Demo Resume
    try:
        status, headers, body = http_post(f"{BACKEND_BASE}/api/demo/resume", origin=FRONTEND_URL)
        data = json.loads(body)
        resume_pass = (status == 200 and data.get("status") == "resumed")
        log_test("Resume", resume_pass, f"HTTP {status}, state={data.get('state')}")
    except Exception as e:
        log_test("Resume", False, str(e))

    # 12. Test Demo Stop
    try:
        status, headers, body = http_post(f"{BACKEND_BASE}/api/demo/stop", origin=FRONTEND_URL)
        data = json.loads(body)
        stop_pass = (status == 200 and data.get("status") == "stopped")
        log_test("Stop", stop_pass, f"HTTP {status}, state={data.get('state')}")
    except Exception as e:
        log_test("Stop", False, str(e))

    print("\n" + "=" * 60)
    print("FINAL SUMMARY REPORT")
    print("=" * 60)
    for k, v in results.items():
        print(f"{k}: {v}")
    print(f"PUBLIC URL:  {FRONTEND_URL}")
    print(f"BACKEND URL: {BACKEND_BASE}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_full_pipeline())
