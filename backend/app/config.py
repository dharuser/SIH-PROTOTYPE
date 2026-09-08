"""
Tunable knobs for the simulator and the detection rules.

Everything the demo depends on lives here so thresholds are easy to explain
and easy to change on stage.
"""

# ---------------------------------------------------------------------------
# Threat type identifiers (shared with the frontend)
# ---------------------------------------------------------------------------
THREAT_FLOOD = "flood"
THREAT_PORT_SCAN = "port_scan"
THREAT_EXFILTRATION = "exfiltration"

THREAT_TYPES = (THREAT_FLOOD, THREAT_PORT_SCAN, THREAT_EXFILTRATION)

# Human friendly labels, used in evidence strings and by the UI.
THREAT_LABELS = {
    THREAT_FLOOD: "Flood Attack",
    THREAT_PORT_SCAN: "Port Scan",
    THREAT_EXFILTRATION: "Data Exfiltration",
}

# ---------------------------------------------------------------------------
# Detection rule 1: flood  (many sources -> one destination, fast)
# ---------------------------------------------------------------------------
FLOOD_WINDOW_SECONDS = 5.0
FLOOD_UNIQUE_SOURCE_THRESHOLD = 25
FLOOD_COOLDOWN_SECONDS = 6.0

# ---------------------------------------------------------------------------
# Detection rule 2: port scan  (one source -> many ports on one destination)
# ---------------------------------------------------------------------------
PORT_SCAN_WINDOW_SECONDS = 5.0
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 12
PORT_SCAN_COOLDOWN_SECONDS = 6.0

# ---------------------------------------------------------------------------
# Detection rule 3: data exfiltration  (bytes_out >> bytes_in)
# ---------------------------------------------------------------------------
EXFIL_RATIO_THRESHOLD = 20.0        # bytes_out > 20x bytes_in
EXFIL_MIN_BYTES_OUT = 250_000       # ignore tiny asymmetric flows as noise
EXFIL_COOLDOWN_SECONDS = 2.0

# ---------------------------------------------------------------------------
# Simulator pacing
# ---------------------------------------------------------------------------
NORMAL_TICK_SECONDS = 0.7           # how often a batch of benign flows is emitted
NORMAL_FLOWS_PER_TICK = (1, 3)      # inclusive range

AUTO_ATTACK_FIRST_DELAY_SECONDS = 20.0
AUTO_ATTACK_INTERVAL_SECONDS = (22.0, 35.0)

# How many alerts to keep in memory for late-joining dashboards.
ALERT_HISTORY_SIZE = 200
FLOW_HISTORY_SIZE = 50
