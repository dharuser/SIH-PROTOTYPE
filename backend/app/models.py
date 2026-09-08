"""Data shapes that travel between the simulator, the detectors and the UI."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Timestamp string used on every record. ISO-8601, UTC, timezone aware."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class FlowRecord(BaseModel):
    """
    One unidirectional network flow record, as it would arrive from a tap on a
    one-way link. These are the only fields the detectors are allowed to see.
    """

    timestamp: str
    source_ip: str
    dest_ip: str
    dest_port: int
    bytes_in: int
    bytes_out: int
    protocol: str

    # Internal only: monotonic-ish epoch seconds used for sliding windows.
    # Excluded from every JSON payload so the wire format matches the spec.
    epoch: float = Field(default=0.0, exclude=True)


class Alert(BaseModel):
    """A single detection produced by one of the three rule-based detectors."""

    timestamp: str
    threat_type: str
    source_ip: str
    dest_ip: str
    confidence: float
    evidence: str


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
