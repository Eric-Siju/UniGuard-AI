import asyncio
import websockets
import httpx
import json

SCENARIOS = [
    ("ddos", "DDoS"),
    ("port_scan", "Port Scan"),
    ("botnet", "Botnet C2"),
    ("dns_tunneling", "DGA / DNS Tunneling"),
    ("encrypted_traffic", "Suspicious Encrypted Traffic"),
    ("exfiltration", "Data Exfiltration"),
]

async def test_scenarios():
    uri = "ws://127.0.0.1:8000/ws/alerts"
    async with websockets.connect(uri) as ws:
        await ws.recv() # init_status

        for scenario, expected_threat in SCENARIOS:
            print(f"\n[*] Testing Scenario: '{scenario}' expecting '{expected_threat}'...")
            async with httpx.AsyncClient() as client:
                await client.post("http://127.0.0.1:8000/api/demo/start", json={"scenario": scenario, "speed": 10.0})

            detected = False
            for _ in range(50):
                msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
                data = json.loads(msg)
                if data.get("type") == "flow_event" and data.get("alert"):
                    alt = data["alert"]
                    if expected_threat in alt["threat_type"]:
                        print(f"  [CONFIRMED] {alt['threat_type']} detected! Conf={float(alt['confidence'])*100:.0f}%, Sev={alt['severity']}")
                        detected = True
                        break

            async with httpx.AsyncClient() as client:
                await client.post("http://127.0.0.1:8000/api/demo/stop")

            assert detected, f"Failed to detect {expected_threat} in scenario {scenario}"
            await asyncio.sleep(0.1)

    print("\n" + "=" * 60)
    print("ALL 6 REQUIRED THREAT CLASSES VERIFIED IN LIVE STREAMING!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_scenarios())
