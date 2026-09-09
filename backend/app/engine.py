"""
Simulation service: wires the traffic generator to the detection engine and
pushes everything out over WebSocket.

Flow of control (strictly one direction, top to bottom):

    generator  ->  detectors  ->  alert history + counters  ->  WebSocket

There is no path back from this module into the generator's "network". That
mirrors the real constraint of a unidirectional link: we observe, we never
transmit.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque

from . import config, generator, models
from .detectors import DetectionEngine
from .hub import ConnectionHub
from .models import Alert, FlowRecord, SimulationStats, utc_now_iso

logger = logging.getLogger(__name__)


class SimulationService:
    def __init__(self) -> None:
        self.hub = ConnectionHub()
        self.detection = DetectionEngine()

        self._running = False
        self._flows_processed = 0
        self._alerts_raised = 0
        self._alerts_by_type: dict[str, int] = {name: 0 for name in config.THREAT_TYPES}
        self._started_at: str | None = None

        # Live sensor bookkeeping
        self._live_flows = 0
        self._simulated_flows = 0
        self._sensor_host: str | None = None
        self._sensor_interface: str | None = None
        self._sensor_last_seen: float | None = None
        self._sensor_last_seen_iso: str | None = None

        self._alert_history: Deque[Alert] = deque(maxlen=config.ALERT_HISTORY_SIZE)
        self._flow_history: Deque[FlowRecord] = deque(maxlen=config.FLOW_HISTORY_SIZE)

        self._emit_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task[None]] = []

    # -- lifecycle ---------------------------------------------------------

    async def startup(self) -> None:
        """Launch the background loops. They idle until the sim is started."""
        loop = asyncio.get_running_loop()
        self._tasks = [
            loop.create_task(self._normal_traffic_loop()),
            loop.create_task(self._auto_attack_loop()),
        ]

    async def shutdown(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        await self.hub.shutdown()

    # -- state -------------------------------------------------------------

    SENSOR_TIMEOUT_SECONDS = 15.0

    def stats(self) -> SimulationStats:
        sensor_live = (
            self._sensor_last_seen is not None
            and (time.monotonic() - self._sensor_last_seen) < self.SENSOR_TIMEOUT_SECONDS
        )
        return SimulationStats(
            running=self._running,
            flows_processed=self._flows_processed,
            alerts_raised=self._alerts_raised,
            alerts_by_type=dict(self._alerts_by_type),
            started_at=self._started_at,
            live_flows=self._live_flows,
            simulated_flows=self._simulated_flows,
            sensor_connected=sensor_live,
            sensor_host=self._sensor_host,
            sensor_interface=self._sensor_interface,
            sensor_last_seen=self._sensor_last_seen_iso,
        )

    def snapshot(self) -> dict[str, Any]:
        """Everything a freshly connected dashboard needs to render at once."""
        return {
            "stats": self.stats().model_dump(),
            "alerts": [alert.model_dump() for alert in self._alert_history],
            "flows": [flow.model_dump() for flow in self._flow_history],
            "thresholds": {
                "flood_unique_sources": config.FLOOD_UNIQUE_SOURCE_THRESHOLD,
                "flood_window_seconds": config.FLOOD_WINDOW_SECONDS,
                "port_scan_unique_ports": config.PORT_SCAN_UNIQUE_PORT_THRESHOLD,
                "port_scan_window_seconds": config.PORT_SCAN_WINDOW_SECONDS,
                "exfiltration_ratio": config.EXFIL_RATIO_THRESHOLD,
            },
        }

    def recent_alerts(self, limit: int = 20) -> list[Alert]:
        alerts = list(self._alert_history)
        return alerts[-limit:][::-1]  # newest first

    async def start(self) -> SimulationStats:
        if not self._running:
            self._running = True
            self._started_at = utc_now_iso()
            logger.info("simulation started")
            await self._broadcast_status()
        return self.stats()

    async def stop(self) -> SimulationStats:
        if self._running:
            self._running = False
            logger.info("simulation stopped")
            await self._broadcast_status()
        return self.stats()

    async def reset(self) -> SimulationStats:
        async with self._emit_lock:
            self._flows_processed = 0
            self._alerts_raised = 0
            self._alerts_by_type = {name: 0 for name in config.THREAT_TYPES}
            self._alert_history.clear()
            self._flow_history.clear()
            self._live_flows = 0
            self._simulated_flows = 0
            self.detection.reset()
            self._started_at = utc_now_iso() if self._running else None
        logger.info("simulation reset")
        self.hub.broadcast({"type": "reset", "data": self.stats().model_dump()})
        return self.stats()

    # -- attack triggers ---------------------------------------------------

    async def trigger_attack(self, threat_type: str) -> dict[str, Any]:
        """
        Replay one attack scenario on demand.

        Works whether or not the background simulation is running, so a demo
        can always fire an attack and get an alert.
        """
        if threat_type not in generator.SCENARIO_BUILDERS:
            raise KeyError(threat_type)

        records, gap = generator.build_scenario(threat_type)

        self.hub.broadcast(
            {
                "type": "scenario_started",
                "data": {
                    "threat_type": threat_type,
                    "label": config.THREAT_LABELS[threat_type],
                    "flow_count": len(records),
                },
            }
        )

        asyncio.create_task(self._replay(records, gap))

        return {
            "threat_type": threat_type,
            "label": config.THREAT_LABELS[threat_type],
            "flows_injected": len(records),
            "estimated_seconds": round(len(records) * gap, 1),
        }

    # -- live sensor ingest ------------------------------------------------

    async def ingest_flows(
        self,
        records: list[FlowRecord],
        host: str | None = None,
        interface: str | None = None,
    ) -> dict[str, Any]:
        """
        Accept real flow records captured from a network interface.

        These go through exactly the same detectors, thresholds and cooldowns as
        simulated traffic. That is the whole point: the rules cannot tell the
        difference, so a detection on live traffic proves the rules work on live
        traffic, not just on data we invented.

        Runs regardless of whether the simulator is started, so a sensor can feed
        a dashboard with the synthetic generator switched off entirely.
        """
        self._sensor_host = host or self._sensor_host
        self._sensor_interface = interface or self._sensor_interface
        self._sensor_last_seen = time.monotonic()
        self._sensor_last_seen_iso = utc_now_iso()

        alerts_before = self._alerts_raised

        # Rebuild each record's sliding-window clock from the timestamp the
        # sensor actually observed, anchored so the newest record is "now".
        # Without this every flow in a batch would share one instant, and the
        # evidence strings would claim things like "12 ports in 0.0s". Keeping
        # the real spacing also means a scan spread over an hour correctly fails
        # to trip a 5-second rule.
        now = time.monotonic()
        pairs: list[tuple[FlowRecord, float]] = []
        for record in records:
            try:
                pairs.append(
                    (record, datetime.fromisoformat(record.timestamp).timestamp())
                )
            except (ValueError, TypeError):
                pairs.append((record, 0.0))

        # A batch is a dictionary drain, so it arrives in arbitrary order. The
        # detectors' sliding windows prune from the front and assume time only
        # moves forward, so feed them chronologically.
        pairs.sort(key=lambda item: item[1])
        newest = max((t for _, t in pairs if t > 0), default=0.0)

        async with self._emit_lock:
            for record, seen_at in pairs:
                record.source = models.SOURCE_LIVE
                if seen_at > 0 and newest > 0:
                    record.epoch = now - (newest - seen_at)
                else:
                    record.epoch = now
                await self._process(record, restamp=False, reuse_epoch=True)

        return {
            "accepted": len(records),
            "alerts_raised": self._alerts_raised - alerts_before,
            "live_flows_total": self._live_flows,
        }

    async def _replay(self, records: list[FlowRecord], gap: float) -> None:
        """Feed a pre-built burst into the pipeline, paced so the UI can follow."""
        async with self._emit_lock:
            for record in records:
                await self._process(record)
                await asyncio.sleep(gap)

    # -- background loops --------------------------------------------------

    async def _normal_traffic_loop(self) -> None:
        while True:
            try:
                if self._running:
                    batch = generator.normal_batch()
                    async with self._emit_lock:
                        for record in batch:
                            await self._process(record)
                await asyncio.sleep(config.NORMAL_TICK_SECONDS)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("normal traffic loop error")
                await asyncio.sleep(1.0)

    async def _auto_attack_loop(self) -> None:
        """Periodically fire one of the three scenarios while running."""
        await asyncio.sleep(config.AUTO_ATTACK_FIRST_DELAY_SECONDS)
        queue: list[str] = []

        while True:
            try:
                if self._running:
                    if not queue:
                        queue = list(config.THREAT_TYPES)
                        random.shuffle(queue)
                    await self.trigger_attack(queue.pop())

                low, high = config.AUTO_ATTACK_INTERVAL_SECONDS
                await asyncio.sleep(random.uniform(low, high))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("auto attack loop error")
                await asyncio.sleep(5.0)

    # -- the read-only pipeline -------------------------------------------

    async def _process(
        self, record: FlowRecord, restamp: bool = True, reuse_epoch: bool = False
    ) -> None:
        # Simulated records are stamped at the moment they are released.
        # Captured records keep the timestamp the sensor observed; their window
        # clock is set by the caller from that timestamp.
        if restamp:
            flow = generator.stamp_now(record)
        elif reuse_epoch:
            flow = record
        else:
            flow = generator.stamp_epoch(record)

        self._flows_processed += 1
        if flow.source == models.SOURCE_LIVE:
            self._live_flows += 1
        else:
            self._simulated_flows += 1
        self._flow_history.append(flow)

        alerts = self.detection.analyze(flow)

        # Book the alerts before broadcasting, so the counters the dashboard
        # receives already include the rows it is about to be handed.
        for alert in alerts:
            self._alerts_raised += 1
            self._alerts_by_type[alert.threat_type] = (
                self._alerts_by_type.get(alert.threat_type, 0) + 1
            )
            self._alert_history.append(alert)

        stats = self.stats().model_dump()

        # Non-blocking: these only enqueue, so detection timing stays
        # independent of how fast any dashboard is reading.
        self.hub.broadcast({"type": "flow", "data": flow.model_dump(), "stats": stats})
        for alert in alerts:
            self.hub.broadcast(
                {"type": "alert", "data": alert.model_dump(), "stats": stats}
            )

    async def _broadcast_status(self) -> None:
        self.hub.broadcast({"type": "status", "data": self.stats().model_dump()})
