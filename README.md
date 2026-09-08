# Passive Threat Detector

A prototype that simulates monitoring a **one-way (unidirectional) network link** and
raises explainable, rule-based alerts for three cyber threats. It only ever reads and
analyses traffic — it has no code path that can transmit back into the monitored
network. No database, no authentication, no machine learning.

**What it detects**

| Threat | Rule that fires it | Threshold |
| --- | --- | --- |
| Flood attack | Many different source IPs hitting one destination at once | 25+ unique sources to one dest within 5s |
| Port scan | One source IP probing many ports on one destination | 12+ unique ports, same source→dest pair, within 5s |
| Data exfiltration | A single flow sending out far more than it took in | `bytes_out > 20 × bytes_in` and `bytes_out > 250 KB` |

Every alert carries an `evidence` string in plain English explaining exactly why it fired.

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
| `WS` | `/ws` | Live stream of flow records and alerts |

Trigger an attack without the UI:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/attack/flood
```

WebSocket messages are `{ "type": ..., "data": ..., "stats": ... }` where `type` is one
of `snapshot`, `flow`, `alert`, `status`, `reset`, `scenario_started`.

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
    engine.py          Wires generator -> detectors -> WebSocket
    hub.py             WebSocket fan-out (one queue + writer per client)
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

## Deployment (Render + Vercel)

The two halves are deployed separately and only need to know each other's URL.

### Backend → Render

Create a new **Web Service** from the repo, then set:

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

### Frontend → Vercel

Import the same repo as a new project, then set:

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
