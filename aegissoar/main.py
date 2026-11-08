import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from aegissoar.api.routes_firewall import router as firewall_router
from aegissoar.api.routes_incidents import router as incidents_router
from aegissoar.api.routes_logs import router as logs_router
from aegissoar.api.routes_simulator import router as simulator_router
from aegissoar.api.routes_threat_intel import router as threat_intel_router
from aegissoar.config import STATIC_DIR
from aegissoar.core.detector import detection_engine
from aegissoar.db import get_dashboard_metrics, init_db


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message_type: str, data: dict):
        message = json.dumps({"type": message_type, "data": data})
        to_remove = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                to_remove.append(connection)
        for dead in to_remove:
            self.disconnect(dead)


ws_manager = ConnectionManager()


async def ws_broadcast_handler(msg_type: str, data: dict):
    await ws_manager.broadcast(msg_type, data)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    detection_engine.broadcast_callback = ws_broadcast_handler
    yield


app = FastAPI(
    title="AegisSOAR Security Platform",
    description="Automated Security Orchestration, Automation, and Response (SOAR) & Threat Hunting Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs_router)
app.include_router(incidents_router)
app.include_router(threat_intel_router)
app.include_router(firewall_router)
app.include_router(simulator_router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        metrics = get_dashboard_metrics()
        await websocket.send_text(json.dumps({"type": "INITIAL_METRICS", "data": metrics}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("aegissoar.main:app", host="0.0.0.0", port=8000, reload=True)
