"""
Alert persistence.

The dashboard is live, but an incident review happens afterwards. Without
storage, restarting the analyser destroys the evidence. SQLite ships with
Python, so this costs nothing in dependencies and needs no server.

Writes are best-effort by design: if the database cannot be written, detection
and streaming must carry on regardless. A logging failure is not worth taking
the monitoring offline for.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import Alert

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    threat_type  TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    source_ip    TEXT    NOT NULL,
    dest_ip      TEXT    NOT NULL,
    confidence   REAL    NOT NULL,
    evidence     TEXT    NOT NULL,
    origin       TEXT    NOT NULL,
    technique_id TEXT,
    technique    TEXT,
    tactic       TEXT,
    process      TEXT,
    hostname     TEXT,
    recorded_at  TEXT    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_origin   ON alerts(origin);
"""


class AlertStore:
    def __init__(self, path: str, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        if enabled:
            self._open()

    def _open(self) -> None:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            # check_same_thread=False because FastAPI serves from a thread pool;
            # every access is guarded by self._lock.
            self._connection = sqlite3.connect(
                self.path, check_same_thread=False, timeout=5.0
            )
            self._connection.row_factory = sqlite3.Row
            with self._lock:
                self._connection.executescript(SCHEMA)
                self._connection.commit()
            logger.info("alert store ready at %s", self.path)
        except Exception:
            logger.warning("alert store unavailable, continuing without it", exc_info=True)
            self.enabled = False
            self._connection = None

    @property
    def available(self) -> bool:
        return self.enabled and self._connection is not None

    def record(self, alert: Alert) -> None:
        if not self.available:
            return
        try:
            with self._lock:
                self._connection.execute(
                    """INSERT INTO alerts
                       (timestamp, threat_type, severity, source_ip, dest_ip,
                        confidence, evidence, origin, technique_id, technique,
                        tactic, process, hostname)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        alert.timestamp, alert.threat_type, alert.severity,
                        alert.source_ip, alert.dest_ip, alert.confidence,
                        alert.evidence, alert.source, alert.technique_id,
                        alert.technique, alert.tactic, alert.process,
                        alert.hostname,
                    ),
                )
                self._connection.commit()
        except Exception:
            logger.debug("could not persist alert", exc_info=True)

    def query(self, limit: int = 500, threat_type: str | None = None,
              severity: str | None = None, origin: str | None = None) -> list[dict[str, Any]]:
        if not self.available:
            return []
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if threat_type:
            sql += " AND threat_type = ?"
            params.append(threat_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if origin:
            sql += " AND origin = ?"
            params.append(origin)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        try:
            with self._lock:
                rows = self._connection.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.debug("alert query failed", exc_info=True)
            return []

    def summary(self) -> dict[str, Any]:
        """Aggregate counts for the incident report header."""
        if not self.available:
            return {"available": False, "total": 0}
        try:
            with self._lock:
                total = self._connection.execute(
                    "SELECT COUNT(*) AS n FROM alerts"
                ).fetchone()["n"]
                by_type = {
                    r["threat_type"]: r["n"]
                    for r in self._connection.execute(
                        "SELECT threat_type, COUNT(*) AS n FROM alerts GROUP BY threat_type"
                    )
                }
                by_severity = {
                    r["severity"]: r["n"]
                    for r in self._connection.execute(
                        "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
                    )
                }
                by_origin = {
                    r["origin"]: r["n"]
                    for r in self._connection.execute(
                        "SELECT origin, COUNT(*) AS n FROM alerts GROUP BY origin"
                    )
                }
                window = self._connection.execute(
                    "SELECT MIN(timestamp) AS first, MAX(timestamp) AS last FROM alerts"
                ).fetchone()
            return {
                "available": True,
                "total": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "by_origin": by_origin,
                "first_alert": window["first"],
                "last_alert": window["last"],
            }
        except Exception:
            logger.debug("alert summary failed", exc_info=True)
            return {"available": False, "total": 0}

    def clear(self) -> None:
        if not self.available:
            return
        try:
            with self._lock:
                self._connection.execute("DELETE FROM alerts")
                self._connection.commit()
        except Exception:
            logger.debug("could not clear alert store", exc_info=True)

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
