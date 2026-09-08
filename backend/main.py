"""
Passive Threat Detector - FastAPI backend.

Local dev:  uvicorn main:app --reload          (docs at http://127.0.0.1:8000/docs)
Production: uvicorn main:app --host 0.0.0.0 --port $PORT

The app builds no absolute URLs of its own, so it is scheme-agnostic: the same
code serves ws:// locally and wss:// when a platform such as Render terminates
TLS in front of it.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.engine import SimulationService
from app.models import Alert, SimulationStats

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s")
logger = logging.getLogger("passive-threat-detector")

simulation = SimulationService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await simulation.startup()
    logger.info("CORS allow_origins = %s", ALLOWED_ORIGINS)
    logger.info("backend ready - simulation is idle, POST /api/simulation/start to begin")
    yield
    await simulation.shutdown()


app = FastAPI(
    title="Passive Threat Detector",
    description=(
        "Simulates monitoring of a one-way (unidirectional) network link and raises "
        "rule-based alerts for flood attacks, port scans and data exfiltration. "
        "Read-only by design: it never transmits into the monitored network."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Cross-origin access.
#
# In production the dashboard is served from a different origin (Vercel) than
# this API (Render), so the browser requires CORS headers. Defaults to "*" for
# demo convenience; set ALLOWED_ORIGINS to a comma-separated list of exact
# origins to lock it down, e.g.
#     ALLOWED_ORIGINS=https://my-app.vercel.app,http://localhost:5173
#
# SECURITY NOTE: "*" lets any website on the internet call this API. That is
# acceptable here only because every endpoint is unauthenticated and read-only
# apart from the demo simulation controls, and there is no user data to leak.
# Narrow it before this becomes anything more than a prototype.
_origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
ALLOWED_ORIGINS = (
    ["*"]
    if _origins_env == "*"
    else [origin.strip() for origin in _origins_env.split(",") if origin.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Must stay False while allow_origins is "*" - browsers reject the
    # wildcard-plus-credentials combination outright.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# REST
# ---------------------------------------------------------------------------


@app.get("/api/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "passive-threat-detector"}


@app.get("/api/status", response_model=SimulationStats, tags=["simulation"])
async def get_status() -> SimulationStats:
    """Current counters and whether the simulation is running."""
    return simulation.stats()


@app.get("/api/snapshot", tags=["simulation"])
async def get_snapshot() -> dict:
    """Everything needed to render the dashboard in one call."""
    return simulation.snapshot()


@app.get("/api/alerts", response_model=list[Alert], tags=["alerts"])
async def get_alerts(limit: int = 20) -> list[Alert]:
    """Most recent alerts, newest first."""
    return simulation.recent_alerts(limit=max(1, min(limit, config.ALERT_HISTORY_SIZE)))


@app.post("/api/simulation/start", response_model=SimulationStats, tags=["simulation"])
async def start_simulation() -> SimulationStats:
    return await simulation.start()


@app.post("/api/simulation/stop", response_model=SimulationStats, tags=["simulation"])
async def stop_simulation() -> SimulationStats:
    return await simulation.stop()


@app.post("/api/simulation/reset", response_model=SimulationStats, tags=["simulation"])
async def reset_simulation() -> SimulationStats:
    """Clear all counters, alert history and detector sliding windows."""
    return await simulation.reset()


@app.post("/api/attack/{threat_type}", tags=["attacks"])
async def trigger_attack(threat_type: str) -> dict:
    """
    Fire one attack scenario on demand.

    `threat_type` must be one of: flood, port_scan, exfiltration.
    Works whether or not the background simulation is running.
    """
    try:
        return await simulation.trigger_attack(threat_type)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{threat_type}'. Expected one of: "
            + ", ".join(config.THREAT_TYPES),
        )


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


@app.websocket("/ws")
async def stream(websocket: WebSocket) -> None:
    """
    Live stream of flow records and alerts.

    On connect the client receives one `snapshot` message, then a continuous
    series of `flow`, `alert`, `status`, `reset` and `scenario_started` messages.
    """
    await simulation.hub.connect(websocket)
    try:
        # Queued through the hub, not sent directly, so the single writer task
        # owning this socket delivers the snapshot ahead of any live traffic.
        simulation.hub.send_to(websocket, {"type": "snapshot", "data": simulation.snapshot()})
        while True:
            # The dashboard is a pure consumer; this receive only keeps the
            # socket open and lets us notice a disconnect promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("websocket closed unexpectedly", exc_info=True)
    finally:
        await simulation.hub.disconnect(websocket)


# ---------------------------------------------------------------------------
# Entry point for platforms that run `python main.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    # Render (and most PaaS providers) inject the port to listen on via PORT
    # and route external traffic to it. Binding to 0.0.0.0 is required: the
    # default 127.0.0.1 is unreachable from outside the container.
    # 10000 mirrors Render's own default so local behaviour matches.
    port = int(os.getenv("PORT", "10000"))
    host = os.getenv("HOST", "0.0.0.0")  # noqa: S104 - must be externally reachable

    logger.info("starting uvicorn on %s:%d", host, port)
    uvicorn.run("main:app", host=host, port=port, reload=False)
