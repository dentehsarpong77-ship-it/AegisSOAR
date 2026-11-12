from dotenv import load_dotenv
load_dotenv()

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from aegissoar.api.routes_firewall import router as firewall_router
from aegissoar.api.routes_incidents import router as incidents_router
from aegissoar.api.routes_logs import router as logs_router
from aegissoar.api.routes_simulator import router as simulator_router
from aegissoar.api.routes_threat_intel import router as threat_intel_router
from aegissoar.api.routes_ai import router as ai_router
from aegissoar.api.routes_auth import router as auth_router
from aegissoar.api.routes_orgs import router as orgs_router
from aegissoar.api.routes_endpoints import router as endpoints_router
from aegissoar.api.routes_reports import router as reports_router
from aegissoar.api.routes_audit import router as audit_router
from aegissoar.config import STATIC_DIR
from aegissoar.core.detector import detection_engine
from aegissoar.core.security import authenticate_token
from aegissoar.db import get_dashboard_metrics, init_db


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.active_connections:
            self.active_connections[org_id] = []
        self.active_connections[org_id].append(websocket)

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.active_connections:
            if websocket in self.active_connections[org_id]:
                self.active_connections[org_id].remove(websocket)

    async def broadcast(self, message_type: str, data: dict, org_id: str):
        message = json.dumps({"type": message_type, "data": data})
        if org_id not in self.active_connections:
            return
        to_remove = []
        for connection in self.active_connections[org_id]:
            try:
                await connection.send_text(message)
            except Exception:
                to_remove.append(connection)
        for dead in to_remove:
            self.disconnect(dead, org_id)


ws_manager = ConnectionManager()


async def ws_broadcast_handler(msg_type: str, data: dict, org_id: str):
    await ws_manager.broadcast(msg_type, data, org_id)



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
app.include_router(ai_router)
app.include_router(auth_router)
app.include_router(orgs_router)
app.include_router(endpoints_router)
app.include_router(reports_router)
app.include_router(audit_router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    user = authenticate_token(token)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    org_id = user.get("organization_id", "org_default")
    await ws_manager.connect(websocket, org_id)
    try:
        metrics = get_dashboard_metrics(organization_id=org_id)
        await websocket.send_text(json.dumps({"type": "INITIAL_METRICS", "data": metrics}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, org_id)
    except Exception:
        ws_manager.disconnect(websocket, org_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("aegissoar.main:app", host="0.0.0.0", port=8000, reload=True)
