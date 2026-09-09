"""Data shapes that travel between the simulator, the detectors and the UI."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Timestamp string used on every record. ISO-8601, UTC, timezone aware."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


SOURCE_SIMULATED = "simulated"
SOURCE_LIVE = "live"


class FlowRecord(BaseModel):
    """
    One unidirectional network flow record.

    The seven fields below are the only thing the detectors are ever allowed to
    see. That is what makes the data source interchangeable: a record captured
    from a real network interface and a record invented by the simulator are
    indistinguishable to the detection rules.

    `source` is metadata for the dashboard only. No detector reads it, so a live
    record is never judged by a different standard than a simulated one.
    """

    timestamp: str
    source_ip: str
    dest_ip: str
    dest_port: int
    bytes_in: int
    bytes_out: int
    protocol: str

    # "simulated" or "live" - provenance label, shown in the UI.
    source: str = SOURCE_SIMULATED

    # Internal only: monotonic-ish epoch seconds used for sliding windows.
    # Excluded from every JSON payload so the wire format stays clean.
    epoch: float = Field(default=0.0, exclude=True)


class Alert(BaseModel):
    """A single detection produced by one of the three rule-based detectors."""

    timestamp: str
    threat_type: str
    source_ip: str
    dest_ip: str
    confidence: float
    evidence: str

    # Carried through from the flow that triggered it.
    source: str = SOURCE_SIMULATED


class SimulationStats(BaseModel):
    """Counters shown on the dashboard."""

    running: bool = False
    flows_processed: int = 0
    alerts_raised: int = 0
    alerts_by_type: dict[str, int] = Field(
        default_factory=lambda: {
            "flood": 0,
            "port_scan": 0,
            "exfiltration": 0,
        }
    )
    started_at: str | None = None

    # Live sensor telemetry, so the dashboard can prove real traffic is arriving.
    live_flows: int = 0
    simulated_flows: int = 0
    sensor_connected: bool = False
    sensor_host: str | None = None
    sensor_interface: str | None = None
    sensor_last_seen: str | None = None
