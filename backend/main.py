"""
Passive Threat Detector - FastAPI backend.

Local dev:  uvicorn main:app --reload          (docs at http://127.0.0.1:8000/docs)
Production: uvicorn main:app --host 0.0.0.0 --port $PORT

The app builds no absolute URLs of its own, so it is scheme-agnostic: the same
code serves ws:// locally and wss:// when a platform such as Render terminates
TLS in front of it.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import config
from app.engine import SimulationService
from app.models import Alert, FlowRecord, SimulationStats, utc_now_iso

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
# Incident reporting
# ---------------------------------------------------------------------------


@app.get("/api/report", tags=["reporting"])
async def report(limit: int = 500) -> dict:
    """
    Full incident report: aggregate counts plus the stored alert history.

    Backed by SQLite, so it survives a restart of the analyser. This is the
    artefact you would hand to someone reviewing the incident after the fact.
    """
    return {
        "generated_at": utc_now_iso(),
        "summary": simulation.store.summary(),
        "live_session": simulation.stats().model_dump(),
        "mitre_coverage": config.MITRE_MAPPING,
        "alerts": simulation.store.query(limit=max(1, min(limit, 5000))),
    }


@app.get("/api/report.csv", tags=["reporting"])
async def report_csv(limit: int = 1000) -> Response:
    """The same alert history as a spreadsheet-friendly CSV download."""
    rows = simulation.store.query(limit=max(1, min(limit, 5000)))

    columns = [
        "timestamp", "threat_type", "severity", "technique_id", "technique",
        "tactic", "source_ip", "dest_ip", "confidence", "origin", "process",
        "hostname", "evidence",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="threat-report.csv"'
        },
    )


@app.delete("/api/report", tags=["reporting"])
async def clear_report() -> dict:
    """Erase the stored alert history. Live counters are untouched."""
    simulation.store.clear()
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Live sensor ingest
# ---------------------------------------------------------------------------


class SensorBatch(BaseModel):
    """A batch of real flow records captured by the sensor agent."""

    host: str | None = None
    interface: str | None = None
    flows: list[FlowRecord]
    # Real interface-level counters. Kept separate from the flows because they
    # cannot be attributed to individual connections; folding them into a flow's
    # byte fields would be inventing data.
    throughput: dict | None = None


@app.post("/api/ingest", tags=["live sensor"])
async def ingest(batch: SensorBatch) -> dict:
    """
    Receive real network flows from the capture sensor.

    The sensor runs next to the monitored network, reads packets off an interface
    and posts summarised flows here. Traffic only ever moves sensor -> analyser,
    which is the same direction of travel a physical data diode permits.

    These records are analysed by the identical three rules used for simulated
    traffic. Nothing about the detection is relaxed or special-cased.
    """
    if len(batch.flows) > 5000:
        raise HTTPException(status_code=413, detail="Batch too large; send under 5000 flows.")

    return await simulation.ingest_flows(
        batch.flows,
        host=batch.host,
        interface=batch.interface,
        throughput=batch.throughput,
    )


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


async def _handle_command(raw: str) -> None:
    """
    Execute a control command that arrived over the WebSocket.

    The REST endpoints below do exactly the same things, but a REST call is a
    fresh HTTP request that any server instance may answer. When the API is
    hosted on a platform that runs several instances, that means the request can
    easily land on an instance the caller's browser is NOT streaming from, and
    the resulting alert is broadcast to a different set of sockets - the button
    looks dead. Routing controls back down the socket the client is already
    attached to keeps the command and the stream on the same instance.

    Unrecognised or malformed messages are ignored on purpose; the client also
    sends plain "ping" keepalives through here.
    """
    raw = raw.strip()
    if not raw or raw == "ping":
        return

    try:
        message = json.loads(raw)
    except (ValueError, TypeError):
        return
    if not isinstance(message, dict):
        return

    action = message.get("action")

    if action == "trigger_attack":
        threat_type = message.get("threat_type")
        if threat_type in config.THREAT_TYPES:
            await simulation.trigger_attack(threat_type)
    elif action == "start":
        await simulation.start()
    elif action == "stop":
        await simulation.stop()
    elif action == "reset":
        await simulation.reset()


@app.websocket("/ws")
async def stream(websocket: WebSocket) -> None:
    """
    Live stream of flow records and alerts.

    On connect the client receives one `snapshot` message, then a continuous
    series of `flow`, `alert`, `status`, `reset` and `scenario_started` messages.

    The client may also send control commands up this socket as JSON:
        {"action": "start"}
        {"action": "stop"}
        {"action": "reset"}
        {"action": "trigger_attack", "threat_type": "flood"}
    """
    await simulation.hub.connect(websocket)
    try:
        # Queued through the hub, not sent directly, so the single writer task
        # owning this socket delivers the snapshot ahead of any live traffic.
        simulation.hub.send_to(websocket, {"type": "snapshot", "data": simulation.snapshot()})
        while True:
            raw = await websocket.receive_text()
            await _handle_command(raw)
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
