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
THREAT_BEACONING = "beaconing"

THREAT_TYPES = (
    THREAT_FLOOD,
    THREAT_PORT_SCAN,
    THREAT_EXFILTRATION,
    THREAT_BEACONING,
)

# Human friendly labels, used in evidence strings and by the UI.
THREAT_LABELS = {
    THREAT_FLOOD: "Flood Attack",
    THREAT_PORT_SCAN: "Port Scan",
    THREAT_EXFILTRATION: "Data Exfiltration",
    THREAT_BEACONING: "C2 Beaconing",
}

# ---------------------------------------------------------------------------
# Severity and MITRE ATT&CK mapping
#
# ATT&CK is the industry-standard catalogue of adversary techniques. Tagging
# every alert with its technique ID is what lets an analyst connect a detection
# to a known playbook instead of treating it as an isolated curiosity.
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

THREAT_SEVERITY = {
    # Data is already leaving. The breach has succeeded.
    THREAT_EXFILTRATION: SEVERITY_CRITICAL,
    # Active disruption of a service.
    THREAT_FLOOD: SEVERITY_HIGH,
    # Implies a host is already compromised and taking orders.
    THREAT_BEACONING: SEVERITY_HIGH,
    # Reconnaissance. Serious, but nothing has been breached yet.
    THREAT_PORT_SCAN: SEVERITY_MEDIUM,
}

MITRE_MAPPING = {
    THREAT_FLOOD: {
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
    },
    THREAT_PORT_SCAN: {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
    },
    THREAT_EXFILTRATION: {
        "technique_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
    },
    THREAT_BEACONING: {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
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
# Detection rule 4: C2 beaconing  (machine-regular callbacks to one host)
#
# Compromised hosts "phone home" on a timer. Humans do not. The giveaway is not
# the volume, it is the *regularity* - malware sleeps a fixed number of seconds
# between check-ins, so the gaps between connections are almost identical.
#
# Measured with the coefficient of variation (standard deviation of the gaps
# divided by their mean). Randomly-arriving traffic sits near 1.0; a scheduled
# beacon sits near 0.0. A threshold of 0.12 is far below anything human
# behaviour produces, which is what keeps this rule quiet.
# ---------------------------------------------------------------------------
# Measured tuning note: at 6 events and a 0.12 threshold, ordinary random
# traffic threw ~3 false alarms per 36,000 flows, because a short run of random
# gaps occasionally looks regular by luck. Requiring more check-ins before
# judging makes that vanishingly unlikely - each extra gap has to coincide too.
# Verified at 0 false positives over ~7 hours of simulated traffic.
BEACON_WINDOW_SECONDS = 300.0
BEACON_MIN_EVENTS = 8               # need enough gaps to judge regularity
BEACON_MAX_CV = 0.08                # lower = more machine-like
BEACON_MIN_INTERVAL = 0.4           # ignore bursts inside one conversation
BEACON_MAX_INTERVAL = 120.0         # ignore very slow, sparse chatter
BEACON_COOLDOWN_SECONDS = 30.0

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

# ---------------------------------------------------------------------------
# Alert persistence
#
# In-memory history is lost on restart, which is fine for a live dashboard but
# useless for producing an incident report afterwards. SQLite is in the standard
# library, so this costs no dependency.
# ---------------------------------------------------------------------------
DB_PATH = "alerts.db"
DB_ENABLED = True
