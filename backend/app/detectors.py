"""
The detection engine: three explainable, rule-based detectors.

No machine learning, no training data, no state outside a short sliding window.
Every detector answers a single question about the records it has just seen and
writes a plain-English `evidence` string saying exactly why it fired.

All three are strictly read-only: they receive a copy of a flow record and can
only return an Alert. Nothing here can emit a packet.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque

from . import config
from .models import Alert, FlowRecord


def _confidence(*, count: int, threshold: int, span: float, window: float) -> float:
    """
    Score a threshold breach on two explainable factors:

    * speed     - how quickly the threshold was crossed inside the window.
                  25 unique sources in 1 second is worse than in 5 seconds.
    * overshoot - how far past the threshold the count already is.

    Floor is 0.70 (the rule did fire) and the ceiling is 0.99.
    """
    speed = min(max((window - span) / window, 0.0), 1.0)
    overshoot = min(max((count - threshold) / threshold, 0.0), 1.0)
    return round(min(0.99, 0.70 + 0.20 * speed + 0.09 * overshoot), 2)


def _human_bytes(value: int) -> str:
    """Format a byte count for a non-technical reader."""
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if amount < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} GB"


class BaseDetector:
    """Common shape for the three rules."""

    threat_type: str = "unknown"

    def inspect(self, flow: FlowRecord) -> Alert | None:  # pragma: no cover
        raise NotImplementedError

    def reset(self) -> None:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Rule 1 - Flood attack
# "Too many different source IPs are hitting one destination at once."
# ---------------------------------------------------------------------------


class FloodDetector(BaseDetector):
    threat_type = config.THREAT_FLOOD

    def __init__(self) -> None:
        self._by_dest: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        self._cooldown_until: dict[str, float] = {}

    def reset(self) -> None:
        self._by_dest.clear()
        self._cooldown_until.clear()

    def inspect(self, flow: FlowRecord) -> Alert | None:
        window = self._by_dest[flow.dest_ip]
        window.append((flow.epoch, flow.source_ip))

        # Drop anything older than the observation window.
        cutoff = flow.epoch - config.FLOOD_WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.popleft()

        unique_sources = {source for _, source in window}
        count = len(unique_sources)

        if count < config.FLOOD_UNIQUE_SOURCE_THRESHOLD:
            return None

        if flow.epoch < self._cooldown_until.get(flow.dest_ip, 0.0):
            return None
        self._cooldown_until[flow.dest_ip] = flow.epoch + config.FLOOD_COOLDOWN_SECONDS

        span = max(window[-1][0] - window[0][0], 0.01)
        confidence = _confidence(
            count=count,
            threshold=config.FLOOD_UNIQUE_SOURCE_THRESHOLD,
            span=span,
            window=config.FLOOD_WINDOW_SECONDS,
        )

        evidence = (
            f"{count} different source IPs contacted {flow.dest_ip} in {span:.1f}s "
            f"(normal traffic stays under {config.FLOOD_UNIQUE_SOURCE_THRESHOLD})"
        )

        return Alert(
            timestamp=flow.timestamp,
            threat_type=self.threat_type,
            source_ip=f"{count} sources (latest {flow.source_ip})",
            dest_ip=flow.dest_ip,
            confidence=round(confidence, 2),
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Rule 2 - Port scan
# "One source IP is knocking on far too many different ports of one host."
# ---------------------------------------------------------------------------


class PortScanDetector(BaseDetector):
    threat_type = config.THREAT_PORT_SCAN

    def __init__(self) -> None:
        self._by_pair: dict[tuple[str, str], Deque[tuple[float, int]]] = defaultdict(deque)
        self._cooldown_until: dict[tuple[str, str], float] = {}

    def reset(self) -> None:
        self._by_pair.clear()
        self._cooldown_until.clear()

    def inspect(self, flow: FlowRecord) -> Alert | None:
        key = (flow.source_ip, flow.dest_ip)
        window = self._by_pair[key]
        window.append((flow.epoch, flow.dest_port))

        cutoff = flow.epoch - config.PORT_SCAN_WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.popleft()

        unique_ports = {port for _, port in window}
        count = len(unique_ports)

        if count < config.PORT_SCAN_UNIQUE_PORT_THRESHOLD:
            return None

        if flow.epoch < self._cooldown_until.get(key, 0.0):
            return None
        self._cooldown_until[key] = flow.epoch + config.PORT_SCAN_COOLDOWN_SECONDS

        span = max(window[-1][0] - window[0][0], 0.01)
        confidence = _confidence(
            count=count,
            threshold=config.PORT_SCAN_UNIQUE_PORT_THRESHOLD,
            span=span,
            window=config.PORT_SCAN_WINDOW_SECONDS,
        )

        sample = ", ".join(str(port) for port in sorted(unique_ports)[:5])
        evidence = (
            f"{flow.source_ip} probed {count} different ports on {flow.dest_ip} "
            f"in {span:.1f}s (e.g. {sample}...)"
        )

        return Alert(
            timestamp=flow.timestamp,
            threat_type=self.threat_type,
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            confidence=round(confidence, 2),
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Rule 3 - Data exfiltration
# "This flow pushed out vastly more data than it pulled in."
# ---------------------------------------------------------------------------


class ExfiltrationDetector(BaseDetector):
    threat_type = config.THREAT_EXFILTRATION

    def __init__(self) -> None:
        self._cooldown_until: dict[tuple[str, str], float] = {}

    def reset(self) -> None:
        self._cooldown_until.clear()

    def inspect(self, flow: FlowRecord) -> Alert | None:
        if flow.bytes_out < config.EXFIL_MIN_BYTES_OUT:
            return None

        # Guard against divide-by-zero while still catching pure-outbound flows.
        baseline = max(flow.bytes_in, 1)
        ratio = flow.bytes_out / baseline

        if ratio <= config.EXFIL_RATIO_THRESHOLD:
            return None

        key = (flow.source_ip, flow.dest_ip)
        if flow.epoch < self._cooldown_until.get(key, 0.0):
            return None
        self._cooldown_until[key] = flow.epoch + config.EXFIL_COOLDOWN_SECONDS

        confidence = min(0.99, 0.70 + (ratio - config.EXFIL_RATIO_THRESHOLD) / 200.0)

        evidence = (
            f"{_human_bytes(flow.bytes_out)} sent out vs only "
            f"{_human_bytes(flow.bytes_in)} received - {ratio:.0f}x more data leaving "
            f"than entering (limit is {int(config.EXFIL_RATIO_THRESHOLD)}x)"
        )

        return Alert(
            timestamp=flow.timestamp,
            threat_type=self.threat_type,
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            confidence=round(confidence, 2),
            evidence=evidence,
        )


# ---------------------------------------------------------------------------


class DetectionEngine:
    """Runs every flow record past all three rules, in order."""

    def __init__(self) -> None:
        self.detectors: list[BaseDetector] = [
            FloodDetector(),
            PortScanDetector(),
            ExfiltrationDetector(),
        ]

    def reset(self) -> None:
        for detector in self.detectors:
            detector.reset()

    def analyze(self, flow: FlowRecord) -> list[Alert]:
        """Read-only analysis of a single flow. Returns 0..3 alerts."""
        alerts: list[Alert] = []
        for detector in self.detectors:
            alert = detector.inspect(flow)
            if alert is not None:
                alerts.append(alert)
        return alerts
