import asyncio
import websockets
import httpx
import json

async def test_live_ws():
    uri = "ws://127.0.0.1:8000/ws/alerts"
    async with websockets.connect(uri) as ws:
        print("Connected to live WebSocket!")
        msg1 = await asyncio.wait_for(ws.recv(), timeout=5.0)
        data1 = json.loads(msg1)
        print("Received initial message:", data1.get("type"), "state:", data1.get("state"))

        async with httpx.AsyncClient() as client:
            resp = await client.post("http://127.0.0.1:8000/api/demo/start", json={"scenario": "combined_demo", "speed": 5.0})
            print("Started demo stream:", resp.json())

        flow_count = 0
        alert_count = 0
        for _ in range(12):
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            data = json.loads(msg)
            mtype = data.get("type")
            if mtype == "flow_event":
                flow_count += 1
                alt = data.get("alert")
                if alt:
                    alert_count += 1
                    print(f"  [LIVE ALERT] {alt['threat_type']} ({alt['severity']}) - {alt['src_ip']} -> {alt['dst_ip']}:{alt['dst_port']} (conf: {float(alt['confidence'])*100:.0f}%)")
            elif mtype == "init_status":
                print("  [STATE SYNC]", data.get("state"))

        print(f"\n[SUCCESS] Received {flow_count} live flow events and {alert_count} alerts via WebSocket directly from running backend!")

        async with httpx.AsyncClient() as client:
            resp = await client.post("http://127.0.0.1:8000/api/demo/stop")
            print("Stopped demo stream:", resp.json())

if __name__ == "__main__":
    asyncio.run(test_live_ws())
