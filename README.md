# Passive Threat Detector

A prototype that simulates monitoring a **one-way (unidirectional) network link** and
raises explainable, rule-based alerts for three cyber threats. It only ever reads and
analyses traffic — it has no code path that can transmit back into the monitored
network. No database, no authentication, no machine learning.

**What it detects**

| Threat | Rule that fires it | Threshold | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| Flood attack | Many different source IPs hitting one destination at once | 25+ unique sources to one dest within 5s | high | [T1498](https://attack.mitre.org/techniques/T1498/) |
| Port scan | One source IP probing many ports on one destination | 12+ unique ports, same source→dest pair, within 5s | medium | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Data exfiltration | A single flow sending out far more than it took in | `bytes_out > 20 × bytes_in` and `bytes_out > 250 KB` | critical | [T1048](https://attack.mitre.org/techniques/T1048/) |
| C2 beaconing | One host calling the same address on a metronome | 8+ check-ins whose gaps vary by under 8% | high | [T1071](https://attack.mitre.org/techniques/T1071/) |

Every alert carries an `evidence` string in plain English explaining exactly why it
fired, plus a severity and a MITRE ATT&CK technique so it can be tied to a known
adversary playbook rather than read as an isolated curiosity.

**Why beaconing is the interesting one.** The other three rules count things. This
one measures *regularity*: malware sleeps a fixed number of seconds between
check-ins, so the gaps between its connections are nearly identical, while human
browsing is erratic. It is scored with the coefficient of variation — standard
deviation of the gaps over their mean. Random traffic sits near 1.0; a scheduled
beacon sits near 0.0.

Tuning note worth knowing: at 6 check-ins and a 12% threshold this produced ~3
false alarms per 36,000 benign flows, because a short run of random gaps
occasionally looks regular by luck. Requiring 8 check-ins at 8% took that to zero
across ~7 hours of simulated traffic. Heavily-jittered beacons (over ~20%
variation) will evade it — that is the honest limit of the technique.

---

## Prerequisites

- **Python 3.10+** (developed on 3.13)
- **Node.js 18+** (developed on 22)

## 1. Start the backend

Open a terminal in the project root.

```powershell
cd backend
py -m venv .venv                     # Windows.  macOS/Linux: python3 -m venv .venv
.\.venv\Scripts\Activate.ps1         # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend is now on **http://127.0.0.1:8000** (interactive API docs at `/docs`).

## 2. Start the frontend

Open a **second** terminal, leaving the backend running.

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

That is all. The dashboard connects over WebSocket and starts the traffic feed for you,
so you should see counters moving within a second or two.

> The Vite dev server proxies `/api` and `/ws` to port 8000, so both halves are
> same-origin and no configuration is needed.

---

## Running the demo

The dashboard has three big buttons. Each one injects a real attack burst into the
traffic feed, which the detectors then catch live:

- **Simulate Flood Attack** → 45 flows from 45 unique IPs onto one server
- **Simulate Port Scan** → one IP walking 30 ports on one server
- **Simulate Data Exfiltration** → an internal host pushing megabytes outbound

An alert appears in the table within about a second, the counters tick up, and the bar
chart grows. The simulation also fires a random attack on its own roughly every 20–35
seconds, so the dashboard is never static.

`Start` / `Stop` control the benign background traffic. `Reset` clears all counters,
alert history and detector state. The attack buttons work whether or not the background
feed is running.

---

## API reference

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness check |
| `GET` | `/api/status` | Counters + running flag |
| `GET` | `/api/snapshot` | Everything needed to render the dashboard |
| `GET` | `/api/alerts?limit=20` | Recent alerts, newest first |
| `POST` | `/api/simulation/start` | Begin background traffic |
| `POST` | `/api/simulation/stop` | Pause background traffic |
| `POST` | `/api/simulation/reset` | Clear counters, history and detector windows |
| `POST` | `/api/attack/{threat_type}` | Trigger `flood`, `port_scan` or `exfiltration` |
| `POST` | `/api/ingest` | Receive real captured flows from the sensor |
| `GET` | `/api/report` | Full incident report (JSON) from stored history |
| `GET` | `/api/report.csv` | Same report as a CSV download |
| `DELETE` | `/api/report` | Erase stored alert history |
| `WS` | `/ws` | Live stream of flow records and alerts |

Alerts are persisted to SQLite (`backend/alerts.db`, standard library, no server),
so the report survives a restart. Resetting the live counters deliberately does
*not* wipe stored history — the dashboard is for watching, the report is evidence.

Trigger an attack without the UI:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/attack/flood
```

WebSocket messages from the server are `{ "type": ..., "data": ..., "stats": ... }`
where `type` is one of `snapshot`, `flow`, `alert`, `status`, `reset`,
`scenario_started`.

The client may also send controls **up** the same socket:

```json
{"action": "start"}
{"action": "stop"}
{"action": "reset"}
{"action": "trigger_attack", "threat_type": "flood"}
```

The dashboard prefers this over the equivalent REST calls, and it is not a
stylistic choice. The API can run on more than one instance. A REST control call
is a fresh HTTP request that any instance may answer, so an attack triggered from
the browser was often executed on an instance that browser was not streaming
from — the alert was broadcast to a different set of sockets and the button
looked dead. Measured on the live deployment: **1 of 5** concurrent viewers saw
the alert they triggered. Sending the command up the socket the client is already
attached to guarantees the trigger and the stream share an instance, which took
it to **5 of 5**. REST remains as a fallback for when the socket isn't open.

---

## Project layout

```
backend/
  main.py              FastAPI app: REST endpoints + /ws WebSocket
  requirements.txt
  app/
    config.py          All thresholds and pacing in one place
    models.py          FlowRecord, Alert, SimulationStats
    generator.py       Synthetic traffic + the three attack scenarios
    detectors.py       The three rules and the evidence strings
    engine.py          Wires generator -> detectors -> WebSocket, plus ingest
    hub.py             WebSocket fan-out (one queue + writer per client)
sensor/
  agent.py             Real packet capture -> flow records -> /api/ingest
                       (stdlib only; live interface or .pcap replay)
frontend/
  vite.config.js       Dev server + /api and /ws proxy to port 8000
  src/
    App.jsx            Page layout
    useTelemetry.js    WebSocket client with auto-reconnect
    api.js             REST helpers
    threats.js         Threat labels and badge colours
    styles.css         All styling (plain CSS, no UI library)
    components/        StatCards, ControlPanel, AlertTable, ThreatChart,
                       FlowTicker, HowItWorks, ThreatBadge
```

---

## Design notes

**The data source is interchangeable.** Detectors receive seven fields and nothing
else — no handle to the generator, no notion of where a record came from. That is
why the same rules run unchanged over real captured packets. It is also the honest
answer to "is this only synthetic?": run `sensor/agent.py` and watch real traffic
go through the identical pipeline.

**Benign traffic cannot produce a false positive.** This is structural, not luck. The
generator's client pool holds 18 hosts (below the 25-source flood threshold), benign
traffic uses 6 ports (below the 12-port scan threshold), and benign byte ratios are
capped at 4× (below the 20× exfiltration ratio). Verified over ~24,000 simulated flows
and again with 5,000 flows compressed into a single instant: zero false positives.

**Detection never waits on the dashboard.** Each browser gets its own bounded outbound
queue and writer task, so broadcasting cannot slow the analysis loop. Without this, a
slow client stretched a flood burst past its own 5-second detection window and the rule
stopped firing.

**Confidence is derived, not hardcoded.** It scores how fast a threshold was crossed and
how far past it the count already is, so repeated demos show varying, defensible numbers.

---

## Live capture: analysing real network traffic

The simulator exists so a demo is reproducible. It is not the only data source.
`sensor/agent.py` reads **real packets** off a network interface, summarises them
into the same seven-field flow records, and posts them to the analyser.

**The detection code is not involved in this distinction.** Detectors only ever
see the seven fields, and `source` is metadata no rule reads. A live record is
judged by identical thresholds and identical cooldowns. That is the point: a
detection on captured traffic proves the rules work on captured traffic.

The sensor also mirrors the architecture being modelled — it reads packets and
sends summaries in one direction, and the analyser has no channel back to it.

### Three capture modes

| Mode | Needs admin | Endpoints, ports, timing | Byte volumes | Process names |
| --- | --- | --- | --- | --- |
| `packet` | **yes** | ✓ | ✓ | ✓ |
| `connection` | no | ✓ | ✗ | ✓ |
| `pcap` replay | no | ✓ | ✓ | ✗ |

`connection` mode reads the operating system's own connection table. It gives
genuine endpoints, ports, protocol and the owning program with no privileges at
all. It has two honest limitations, both measured rather than assumed:

**No byte volumes.** Neither Windows nor Linux exposes per-connection counters to
an unprivileged process. Those fields are reported as zero rather than estimated,
so the exfiltration rule stays silent in this mode instead of firing on numbers
nobody measured.

**It samples, so it can miss short connections.** The connection table is polled
on an interval; a request that opens and closes between two polls is never seen.
Measured directly: 12 deliberately-timed HTTPS requests produced only 5 captured
flows, and the beaconing rule correctly did not fire because it never received
enough events. Connection mode is therefore excellent for proving the data is
real and attributing it to a program, but it is a sampled view, not a complete
one.

**Use `packet` mode for actual detection work.** It sees every packet, measures
real volumes, and misses nothing. That is the mode to run for a serious demo.

Measured on a normal Windows laptop with no elevation: 82 real flows captured,
process names on 44 of 50 (`brave.exe`, `node.exe`, `AvastSvc.exe`, `svchost.exe`),
reverse DNS resolving to `ec2-*.compute-1.amazonaws.com`, interface throughput up
to 356 KB/s — and zero false positives on genuine traffic.

The sensor also reports real interface throughput separately from flow records,
because those totals are true but cannot be attributed to individual connections.
Folding them into a flow's byte fields would be inventing data.

### Run it

Optional but recommended, for process names and no-privilege mode:

```powershell
cd sensor
pip install -r requirements.txt      # psutil
```

Then, with the analyser and dashboard already running:

```powershell
cd sensor
py agent.py --list                   # shows which modes are available to you
py agent.py                          # auto-selects the best available mode
```

Packet capture is a privileged operation on every OS, so use an elevated shell
for full fidelity.

```powershell
# Terminal 1 - analyser
cd backend
uvicorn main:app --port 8000

# Terminal 2 - dashboard
cd frontend
npm run dev

# Terminal 3 - AS ADMINISTRATOR
cd sensor
py agent.py --backend http://127.0.0.1:8000
```

The dashboard's **Data source** panel switches to `LIVE CAPTURE`, and every
captured alert is tagged `LIVE` in the alerts table.

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--list` | show capabilities and which mode would be auto-selected |
| `--mode connection` | force no-privilege mode |
| `--mode packet` | force raw packet capture (needs admin) |
| `--pcap FILE` | replay a real `.pcap` — **no privileges needed** |
| `--dry-run` | print flows without sending them |
| `--interface IP` | Windows: which local IP to bind. Linux: interface name |
| `--duration N` | stop after N seconds |

### If you cannot get Administrator

Capture in Wireshark, save as **pcap** (not pcapng), and replay it:

```powershell
py agent.py --pcap capture.pcap --backend http://127.0.0.1:8000
```

The packets are still genuine, just recorded earlier. Replay preserves each
packet's original timestamp, so a scan recorded over 4 seconds is analysed as
having taken 4 seconds.

### What live traffic actually triggers

**Exfiltration is the reliable live demo.** Upload a large file to any cloud
service and the rule fires, because a bulk upload genuinely is far more data
leaving than entering. Verified on a real capture: *309.4 KB sent out vs only
2.0 KB received — 158x more data leaving than entering.*

Port scans fire if something scans the machine, or if you scan a host yourself.
Floods need many distinct source IPs, which is hard to produce honestly on one
laptop — that is what the simulator button is for. Being straightforward about
this is stronger than pretending otherwise.

### Important: live mode needs a single-instance backend

Run the analyser **locally** for live capture, or on a single-instance host such
as Render. On Vercel the API is replicated, so the sensor's batch may be received
by a different instance than the dashboard is streaming from, and the captured
flows would not appear on screen. Same root cause as the WebSocket control
decision documented above.

---

## Deployment

Both halves are deployed as **two separate Vercel projects from this one repo**,
distinguished only by their Root Directory. They are live at:

| Part | URL | Root Directory |
| --- | --- | --- |
| Dashboard | https://sih-prototype-dashboard.vercel.app | `frontend` |
| API | https://sih-prototype-lvry.vercel.app | `backend` |

The frontend project sets `VITE_API_URL` and `VITE_WS_URL` to the API project's
origin. Nothing else connects them.

**Root Directory is the setting that matters.** With two apps in one repo and no
Root Directory set, Vercel scans from the top, finds `backend/requirements.txt`,
decides the project is Python, and builds the wrong half. That is the single
most likely thing to go wrong when redeploying from scratch.

Vercel runs the FastAPI backend on persistent instances, so the always-on
background simulation and the streaming WebSocket both work — verified live over
a 3-minute connection.

**Vercel does run several instances under concurrent load**, and each holds its
own in-memory state and its own traffic generator. That is why dashboard controls
travel up the WebSocket rather than over REST (see the API section above).
Consequence worth knowing: each viewer effectively gets an independent
simulation, with their own counters and their own attack bursts. Two people
watching see different numbers. For a demo that is fine, arguably better — nobody
can reset anyone else's screen.

### Alternative: backend → Render

Render runs a single always-on instance, which removes the multi-instance caveat
above at the cost of a ~50s cold start on the free tier. Create a **Web Service**
from the repo, then set:

| Setting | Value |
| --- | --- |
| Root Directory | `backend` |
| Language / Runtime | `Python 3` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/api/health` |

Environment variables:

| Key | Value | Required |
| --- | --- | --- |
| `PYTHON_VERSION` | `3.13` | Recommended |
| `ALLOWED_ORIGINS` | `*` (default) or `https://your-app.vercel.app` | Optional |

`PORT` is injected by Render — do not set it yourself. Pin `PYTHON_VERSION`
because Render's current default is 3.14, and the versions pinned in
`requirements.txt` were only verified on 3.13.

Use the minor version (`3.13`), not an exact patch. Both Render and Vercel now
provision Python through `uv`, which resolves `3.13` to whatever 3.13.x it has
available. Asking for a specific patch it hasn't cached fails the build with
`No interpreter found for Python 3.13.x`.

If you switch to Render, update `VITE_API_URL` / `VITE_WS_URL` in the Vercel
frontend project to the Render origin and redeploy.

### Frontend → Vercel

Import the repo as a new project, then set:

| Setting | Value |
| --- | --- |
| Root Directory | `frontend` |
| Framework Preset | `Vite` |
| Build Command | `npm run build` |
| Output Directory | `dist` |
| Install Command | `npm install` |

Environment variables (both for Production, Preview and Development):

| Key | Value |
| --- | --- |
| `VITE_API_URL` | `https://<your-render-service>.onrender.com` |
| `VITE_WS_URL` | `wss://<your-render-service>.onrender.com/ws` |

See `frontend/.env.example`. Vite inlines these at **build** time, so changing
them in Vercel requires a redeploy to take effect.

### How the URLs resolve

`frontend/src/api.js` is the single place backend location is decided:

- **Both unset** → relative `/api` paths and same-origin WebSocket. This is what
  makes local `npm run dev` work through the Vite proxy with no `.env` file.
- **`VITE_API_URL` set, `VITE_WS_URL` unset** → the socket URL is derived by
  swapping the scheme, so `https://` yields `wss://` automatically.
- **Both set** → used as given.

The `ws:`/`wss:` scheme is never hardcoded; it is always derived from either the
API URL or `window.location.protocol`. An `https://` page therefore always gets
`wss://`, which is required — browsers block a plaintext `ws://` socket opened
from an HTTPS page as mixed content.

The backend never constructs absolute URLs, so it is scheme-agnostic and needs
no change to serve WSS behind Render's TLS-terminating proxy.

> **Free tier caveat:** a Render free service sleeps after ~15 minutes idle. The
> first request then takes ~50s to wake, and because all state is in memory, the
> counters and alert history start from zero. The dashboard reconnects on its
> own, but load the page once before a live demo to warm the service up.

---

## Troubleshooting

**`python` is not recognised (Windows).** Use the `py` launcher, as shown above, or run
`py -m uvicorn main:app --reload`.

**`npm install` hangs, or fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.** Your network
inspects TLS (common on corporate or campus Wi-Fi) and npm does not trust the
intercepting certificate. Tell Node to use the operating system's certificate store:

```powershell
$env:NODE_OPTIONS="--use-system-ca"     # macOS/Linux: export NODE_OPTIONS=--use-system-ca
npm install
```

This keeps certificate verification switched on. Prefer it over
`npm config set strict-ssl false`, which disables verification entirely.

**Build fails with `Cannot find module '@tailwindcss/postcss'`.** A stray
`postcss.config.*` somewhere above this folder is being picked up. `vite.config.js`
already sets an inline empty PostCSS config to block that search; keep it.

**Dashboard shows "Feed offline".** The backend is not running or is on a different
port. Confirm http://127.0.0.1:8000/api/health returns `{"status":"ok"}`.

**Counters jumped back to zero on their own.** All state is in memory, and `--reload`
restarts the server whenever a file under `backend/` changes — which clears it. Harmless
while developing; drop `--reload` if you want the counters to survive a long demo.

**Port already in use.** Run the backend on another port with
`uvicorn main:app --reload --port 8001`, then update the two `target` values in
`frontend/vite.config.js` to match.
