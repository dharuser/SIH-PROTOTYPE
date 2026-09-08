"""
Tracks connected dashboards and fans messages out to all of them.

Each client gets its own outbound queue and writer task. `broadcast()` only
enqueues, it never waits on a socket. That matters: the detection pipeline runs
inside the same event loop, and if broadcasting blocked on a slow or distant
browser, records would be fed to the detectors more slowly than they were
generated. A flood burst could then take longer than the 5-second detection
window and never trip the rule. Analysis speed must not depend on how fast the
dashboard can read.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Deep enough that a briefly-stalled browser loses nothing; bounded so a dead
# connection can never grow without limit.
CLIENT_QUEUE_SIZE = 2000


class _Client:
    """One dashboard connection plus its outbound queue and writer task."""

    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket
        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=CLIENT_QUEUE_SIZE
        )
        self.task: asyncio.Task[None] | None = None
        self.dropped = 0

    def enqueue(self, message: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            # Shed the oldest message so the client stays current instead of
            # falling further behind.
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except asyncio.QueueEmpty:
                pass
            self.dropped += 1
            try:
                self.queue.put_nowait(message)
            except asyncio.QueueFull:
                pass

    async def run_writer(self) -> None:
        while True:
            message = await self.queue.get()
            if message is None:  # shutdown sentinel
                return
            await self.websocket.send_json(message)


class ConnectionHub:
    def __init__(self) -> None:
        self._clients: dict[WebSocket, _Client] = {}

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        client = _Client(websocket)
        self._clients[websocket] = client
        client.task = asyncio.create_task(self._writer_loop(client))
        logger.info("dashboard connected (%d total)", len(self._clients))

    async def disconnect(self, websocket: WebSocket) -> None:
        client = self._clients.pop(websocket, None)
        if client is None:
            return
        if client.task is not None:
            client.task.cancel()
            try:
                await client.task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.debug("writer task ended with an error", exc_info=True)
        if client.dropped:
            logger.warning(
                "dashboard disconnected after falling behind; %d messages shed",
                client.dropped,
            )
        logger.info("dashboard disconnected (%d total)", len(self._clients))

    async def _writer_loop(self, client: _Client) -> None:
        try:
            await client.run_writer()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Socket died mid-send. Drop the client; the endpoint's own
            # receive loop will also notice and clean up.
            logger.debug("client writer stopped", exc_info=True)
            self._clients.pop(client.websocket, None)

    def broadcast(self, message: dict[str, Any]) -> None:
        """
        Queue one JSON message for every connected dashboard.

        Deliberately synchronous and non-blocking: callers on the detection
        path must never wait for network I/O.
        """
        for client in list(self._clients.values()):
            client.enqueue(message)

    def send_to(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """
        Queue a message for one specific client.

        Used for the initial snapshot. Going through the same queue as every
        broadcast is what guarantees the snapshot is the first frame the client
        sees, since a single writer task owns the socket.
        """
        client = self._clients.get(websocket)
        if client is not None:
            client.enqueue(message)

    async def shutdown(self) -> None:
        for client in list(self._clients.values()):
            if client.task is not None:
                client.task.cancel()
        self._clients.clear()
