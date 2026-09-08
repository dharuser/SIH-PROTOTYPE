import ThreatBadge from './ThreatBadge'

const MAX_ROWS = 20

function formatTime(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString('en-GB', { hour12: false })
}

function ConfidenceMeter({ value }) {
  const percent = Math.round((value ?? 0) * 100)
  return (
    <div className="confidence">
      <div className="confidence-track">
        <div className="confidence-fill" style={{ width: `${percent}%` }} />
      </div>
      <span className="confidence-text">{percent}%</span>
    </div>
  )
}

/** Live table of the most recent alerts, newest at the top. */
export default function AlertTable({ alerts }) {
  const rows = alerts.slice(0, MAX_ROWS)

  return (
    <section className="panel alerts-panel" aria-labelledby="alerts-heading">
      <div className="panel-header">
        <h2 id="alerts-heading" className="panel-title">
          Live alerts
        </h2>
        <span className="panel-subtitle">Most recent {MAX_ROWS}</span>
      </div>

      <div className="table-scroll">
        <table className="alerts-table">
          <caption className="sr-only">
            Threats detected in the monitored traffic, newest first
          </caption>
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Threat</th>
              <th scope="col">Source</th>
              <th scope="col">Confidence</th>
              <th scope="col">Why it fired</th>
            </tr>
          </thead>
          <tbody aria-live="polite" aria-relevant="additions">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="empty-row">
                  No threats detected yet. Press one of the buttons above to
                  simulate an attack.
                </td>
              </tr>
            ) : (
              rows.map((alert) => (
                <tr key={alert._key}>
                  <td className="mono nowrap">{formatTime(alert.timestamp)}</td>
                  <td>
                    <ThreatBadge threatType={alert.threat_type} />
                  </td>
                  <td className="mono">{alert.source_ip}</td>
                  <td>
                    <ConfidenceMeter value={alert.confidence} />
                  </td>
                  <td className="evidence">{alert.evidence}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
