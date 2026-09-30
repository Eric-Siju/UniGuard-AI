import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

response = client.get("/health", headers={"Origin": "https://uniguard-ai-sih.vercel.app"})
print("Status code:", response.status_code)
print("Access-Control-Allow-Origin:", response.headers.get("access-control-allow-origin"))
print("Access-Control-Allow-Credentials:", response.headers.get("access-control-allow-credentials"))

assert response.headers.get("access-control-allow-origin") == "https://uniguard-ai-sih.vercel.app"
assert response.headers.get("access-control-allow-credentials") == "true"
print("[SUCCESS] CORS verification passed for https://uniguard-ai-sih.vercel.app!")
