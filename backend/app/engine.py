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
from collections import deque
from typing import Any, Deque

from . import config, generator
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

    def stats(self) -> SimulationStats:
        return SimulationStats(
            running=self._running,
            flows_processed=self._flows_processed,
            alerts_raised=self._alerts_raised,
            alerts_by_type=dict(self._alerts_by_type),
            started_at=self._started_at,
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

    async def _process(self, record: FlowRecord) -> None:
        flow = generator.stamp_now(record)

        self._flows_processed += 1
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
