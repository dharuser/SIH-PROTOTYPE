import { useCallback, useEffect, useRef, useState } from 'react'

import AlertTable from './components/AlertTable'
import ControlPanel from './components/ControlPanel'
import FlowTicker from './components/FlowTicker'
import HowItWorks from './components/HowItWorks'
import SourcePanel from './components/SourcePanel'
import StatCards from './components/StatCards'
import ThreatChart from './components/ThreatChart'
import { threatMeta } from './threats'
import { useTelemetry } from './useTelemetry'
import {
  resetSimulation,
  startSimulation,
  stopSimulation,
  triggerAttack,
} from './api'

export default function App() {
  const { connection, stats, alerts, flows, sendCommand } = useTelemetry()
  const [toast, setToast] = useState(null)
  const [busy, setBusy] = useState(false)

  const autoStarted = useRef(false)
  const toastTimer = useRef(null)

  const showToast = useCallback((message, tone = 'info') => {
    setToast({ message, tone })
    clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 3500)
  }, [])

  useEffect(() => () => clearTimeout(toastTimer.current), [])

  // Start the background feed once, the first time we connect, so the
  // dashboard is never sitting empty when someone opens it.
  useEffect(() => {
    if (connection !== 'live' || autoStarted.current) return
    autoStarted.current = true
    if (!stats.running) {
      // Sent over the socket so the instance we are streaming from is the one
      // that starts generating traffic. Falls back to REST if the socket
      // isn't ready yet.
      if (!sendCommand({ action: 'start' })) {
        startSimulation().catch(() => {
          /* the Start button is still available */
        })
      }
    }
  }, [connection, stats.running, sendCommand])

  const handleTriggerAttack = useCallback(
    async (threatType) => {
      setBusy(true)
      const label = threatMeta(threatType).label
      try {
        // Prefer the open socket: a REST call can be answered by a different
        // server instance than the one feeding this page, in which case the
        // alert would never appear here.
        if (sendCommand({ action: 'trigger_attack', threat_type: threatType })) {
          showToast(`${label} injected - watch the alerts table`)
        } else {
          const result = await triggerAttack(threatType)
          showToast(
            `${label} injected - ${result.flows_injected} flow records now being analysed`,
          )
        }
      } catch (error) {
        showToast(`Could not trigger attack: ${error.message}`, 'error')
      } finally {
        // Brief lock so a double-click does not stack two bursts.
        setTimeout(() => setBusy(false), 600)
      }
    },
    [showToast, sendCommand],
  )

  const handleSimAction = useCallback(
    async (action, label, wsAction) => {
      try {
        if (!(wsAction && sendCommand({ action: wsAction }))) {
          await action()
        }
        showToast(label)
      } catch (error) {
        showToast(error.message, 'error')
      }
    },
    [showToast, sendCommand],
  )

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-heading">
          <h1>Passive Threat Detector</h1>
          <p className="app-tagline">
            Watching a one-way network link and explaining every threat it finds
          </p>
        </div>
        <span
          className={`link-pill ${connection === 'live' ? 'link-pill-live' : 'link-pill-off'}`}
        >
          <span className="status-dot" aria-hidden="true" />
          {connection === 'live' ? 'Read-only feed connected' : 'Feed offline'}
        </span>
      </header>

      <StatCards
        stats={stats}
        running={stats.running}
        connection={connection}
      />

      <ControlPanel
        running={stats.running}
        busy={busy}
        onTriggerAttack={handleTriggerAttack}
        onStart={() =>
          handleSimAction(startSimulation, 'Background traffic started', 'start')
        }
        onStop={() =>
          handleSimAction(stopSimulation, 'Background traffic paused', 'stop')
        }
        onReset={() =>
          handleSimAction(
            resetSimulation,
            'Counters and alert history cleared',
            'reset',
          )
        }
      />

      <div className="dashboard-grid">
        <AlertTable alerts={alerts} />
        <div className="side-column">
          <SourcePanel stats={stats} />
          <ThreatChart countsByType={stats.alerts_by_type} />
          <FlowTicker flows={flows} />
        </div>
      </div>

      <HowItWorks />

      <div className="toast-area" aria-live="polite" aria-atomic="true">
        {toast && (
          <div className={`toast toast-${toast.tone}`}>{toast.message}</div>
        )}
      </div>
    </div>
  )
}
