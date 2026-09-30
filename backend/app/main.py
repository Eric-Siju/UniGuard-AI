"""
UniGuard AI - Main FastAPI Application
Passive Unidirectional Cyber Threat Detection Platform
Smart India Hackathon 2026 (Problem Statement SIH26145)
"""

import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from backend.app.core.config import settings
from backend.app.models.database import init_db
from backend.app.api.endpoints import router as api_router
from backend.app.engine.streamer import stream_engine
from backend.app.engine.ml_detector import ml_detector

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure SQLite database schema & load ML model checkpoints
    print(f"[*] Starting {settings.APP_NAME} v{settings.APP_VERSION}...")
    init_db()
    if not ml_detector.is_loaded:
        ml_detector.load_models()
    print("[?] UniGuard AI Backend Initialized in PASSIVE READ-ONLY Mode.")
    yield
    # Shutdown: Stop any active streaming workers
    print("[*] Shutting down UniGuard AI...")
    stream_engine.stop_demo()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan
)

# Enable CORS for local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Router
app.include_router(api_router)

# Mount React production build assets as official frontend
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
frontend_assets = os.path.join(frontend_dist, "assets")
if os.path.exists(frontend_assets):
    app.mount("/assets", StaticFiles(directory=frontend_assets), name="assets")

# Mount legacy static files directory if present (fallback)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket feed for live flow telemetry, threat alerts,
    and system status updates directly into the SOC dashboard.
    """
    await stream_engine.connect_client(websocket)
    try:
        while True:
            # Keep connection open; receive client ping or control messages if sent
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        stream_engine.disconnect_client(websocket)
    except Exception:
        stream_engine.disconnect_client(websocket)

@app.get("/")
def root():
    react_index = os.path.join(frontend_dist, "index.html")
    if os.path.exists(react_index):
        return FileResponse(react_index)
    static_index = os.path.join(static_dir, "index.html")
    if os.path.exists(static_index):
        return FileResponse(static_index)
    return {
        "system": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "OPERATIONAL",
        "mode": "PASSIVE_UNIDIRECTIONAL_MONITORING",
        "active_response": False,
        "payload_decryption": False,
        "docs_url": "/docs",
        "health_url": "/health"
    }

@app.get("/{full_path:path}")
def catch_all_spa(full_path: str):
    """Serves the official React SPA index.html for client-side routing on page refresh."""
    if full_path.startswith(("api", "ws", "health", "docs", "openapi.json", "assets", "static")):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Not Found")
    react_index = os.path.join(frontend_dist, "index.html")
    if os.path.exists(react_index):
        return FileResponse(react_index)
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Not Found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
