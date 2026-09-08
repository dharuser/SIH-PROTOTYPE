"""
Synthetic one-way traffic generator.

Produces fake flow records. Nothing here touches a real network interface:
every byte count and IP address is invented locally. The generator is
deliberately tuned so that *benign* traffic can never satisfy any of the three
detection rules -- that keeps the live demo free of false positives.
"""

from __future__ import annotations

import random
import time

from . import config
from .models import FlowRecord, utc_now_iso

# ---------------------------------------------------------------------------
# Fixed "topology" for the simulated environment
# ---------------------------------------------------------------------------

# Protected servers sitting behind the one-way link.
SERVER_POOL = ["10.0.0.5", "10.0.0.12", "10.0.0.23", "10.0.0.31", "10.0.0.44"]

# Ports that benign traffic uses. Fewer than the port-scan threshold on
# purpose, so ordinary chatter can never look like a scan.
COMMON_PORTS = [80, 443, 53, 22, 3389, 8080]

PROTOCOLS = ["TCP", "TCP", "TCP", "UDP"]  # weighted toward TCP

# Internal clients that generate the normal background traffic.
#
# This pool is deliberately kept SMALLER than FLOOD_UNIQUE_SOURCE_THRESHOLD.
# That makes benign traffic structurally incapable of tripping the flood rule --
# no matter how fast it is generated, it can never present more unique sources
# than there are hosts in the pool. Same idea applies to COMMON_PORTS vs the
# port-scan threshold, and to the byte ratios above vs the exfiltration ratio.
CLIENT_POOL = [f"192.168.{block}.{host}" for block in (1, 4) for host in range(10, 19)]
assert len(CLIENT_POOL) < config.FLOOD_UNIQUE_SOURCE_THRESHOLD
assert len(COMMON_PORTS) < config.PORT_SCAN_UNIQUE_PORT_THRESHOLD

# Attacker-ish address space used only by the attack scenarios.
_BOTNET_PREFIXES = ["45", "103", "185", "91", "203", "77"]


def _random_external_ip() -> str:
    return (
        f"{random.choice(_BOTNET_PREFIXES)}."
        f"{random.randint(2, 250)}."
        f"{random.randint(2, 250)}."
        f"{random.randint(2, 250)}"
    )


def _make_flow(
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    bytes_in: int,
    bytes_out: int,
    protocol: str = "TCP",
) -> FlowRecord:
    return FlowRecord(
        timestamp=utc_now_iso(),
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        bytes_in=int(bytes_in),
        bytes_out=int(bytes_out),
        protocol=protocol,
        epoch=time.monotonic(),
    )


# ---------------------------------------------------------------------------
# Benign traffic
# ---------------------------------------------------------------------------


def normal_flow() -> FlowRecord:
    """
    One ordinary flow record.

    Byte ratios are capped well below the exfiltration threshold, and the
    source/port variety is capped well below the flood and scan thresholds.
    """
    bytes_in = random.randint(400, 900_000)

    if random.random() < 0.25:
        # An upload-shaped flow, but still nowhere near 20x asymmetry.
        bytes_out = int(bytes_in * random.uniform(1.2, 4.0))
    else:
        # A download-shaped flow: mostly inbound.
        bytes_out = int(bytes_in * random.uniform(0.05, 0.6)) + random.randint(64, 1_500)

    return _make_flow(
        source_ip=random.choice(CLIENT_POOL),
        dest_ip=random.choice(SERVER_POOL),
        dest_port=random.choice(COMMON_PORTS),
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        protocol=random.choice(PROTOCOLS),
    )


def normal_batch() -> list[FlowRecord]:
    low, high = config.NORMAL_FLOWS_PER_TICK
    return [normal_flow() for _ in range(random.randint(low, high))]


# ---------------------------------------------------------------------------
# Attack scenarios
#
# Each builder returns (records, gap_seconds). The engine replays the records
# with `gap_seconds` between them so the dashboard sees a burst arrive live
# instead of one giant lump.
# ---------------------------------------------------------------------------


def flood_scenario() -> tuple[list[FlowRecord], float]:
    """Many unique source IPs slamming a single destination within seconds."""
    victim = random.choice(SERVER_POOL)
    port = random.choice([80, 443])

    records: list[FlowRecord] = []
    seen: set[str] = set()
    while len(seen) < 45:
        src = _random_external_ip()
        if src in seen:
            continue
        seen.add(src)
        records.append(
            _make_flow(
                source_ip=src,
                dest_ip=victim,
                dest_port=port,
                bytes_in=random.randint(60, 400),
                bytes_out=random.randint(0, 120),
                protocol="TCP",
            )
        )

    # Paced tightly on purpose: the 25-unique-source threshold has to be crossed
    # well inside FLOOD_WINDOW_SECONDS even on a machine with a coarse timer
    # (Windows rounds short sleeps up to roughly 15 ms).
    return records, 0.03


def port_scan_scenario() -> tuple[list[FlowRecord], float]:
    """A single source walking a long list of ports on one destination."""
    attacker = _random_external_ip()
    target = random.choice(SERVER_POOL)

    ports = random.sample(range(20, 9000), 30)
    records = [
        _make_flow(
            source_ip=attacker,
            dest_ip=target,
            dest_port=port,
            bytes_in=random.randint(40, 120),
            bytes_out=random.randint(0, 60),
            protocol="TCP",
        )
        for port in sorted(ports)
    ]

    return records, 0.06


def exfiltration_scenario() -> tuple[list[FlowRecord], float]:
    """An internal host pushing far more data out than it took in."""
    insider = random.choice(CLIENT_POOL)
    external_collector = _random_external_ip()
    port = random.choice([443, 22, 8443])

    records: list[FlowRecord] = []
    for _ in range(2):
        bytes_in = random.randint(2_000, 40_000)
        bytes_out = int(bytes_in * random.uniform(28.0, 90.0)) + config.EXFIL_MIN_BYTES_OUT
        records.append(
            _make_flow(
                source_ip=insider,
                dest_ip=external_collector,
                dest_port=port,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                protocol="TCP",
            )
        )

    return records, 0.35


SCENARIO_BUILDERS = {
    config.THREAT_FLOOD: flood_scenario,
    config.THREAT_PORT_SCAN: port_scan_scenario,
    config.THREAT_EXFILTRATION: exfiltration_scenario,
}


def build_scenario(name: str) -> tuple[list[FlowRecord], float]:
    """Build the flow burst for a named scenario. Raises KeyError if unknown."""
    return SCENARIO_BUILDERS[name]()


def stamp_now(flow: FlowRecord) -> FlowRecord:
    """
    Re-stamp a record at the moment it is actually released into the stream.

    Scenario bursts are built up-front in a tight loop, so their original
    timestamps would all be identical. Re-stamping on release keeps the
    "N events in X seconds" evidence strings honest.
    """
    flow.timestamp = utc_now_iso()
    flow.epoch = time.monotonic()
    return flow
