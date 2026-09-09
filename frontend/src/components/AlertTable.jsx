import ThreatBadge from './ThreatBadge'
import { severityMeta } from '../threats'

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
export default function AlertTable({ alerts, onExport, canExport }) {
  const rows = alerts.slice(0, MAX_ROWS)

  return (
    <section className="panel alerts-panel" aria-labelledby="alerts-heading">
      <div className="panel-header">
        <h2 id="alerts-heading" className="panel-title">
          Live alerts
        </h2>
        <div className="panel-actions">
          <span className="panel-subtitle">Most recent {MAX_ROWS}</span>
          <button
            type="button"
            className="ghost-button ghost-button-sm"
            onClick={onExport}
            disabled={!canExport}
            title="Download the stored alert history as a CSV incident report"
          >
            Export report
          </button>
        </div>
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
              <th scope="col">Severity</th>
              <th scope="col">Source</th>
              <th scope="col">Origin</th>
              <th scope="col">Confidence</th>
              <th scope="col">Why it fired</th>
            </tr>
          </thead>
          <tbody aria-live="polite" aria-relevant="additions">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="empty-row">
                  No threats detected yet. Press one of the buttons above to
                  simulate an attack.
                </td>
              </tr>
            ) : (
              rows.map((alert) => {
                const severity = severityMeta(alert.severity)
                return (
                  <tr
                    key={alert._key}
                    style={{ '--severity-color': severity.color }}
                    className="alert-row"
                  >
                    <td className="mono nowrap">{formatTime(alert.timestamp)}</td>

                    <td>
                      <ThreatBadge threatType={alert.threat_type} />
                      {alert.technique_id && (
                        <span
                          className="mitre-tag mono"
                          title={`MITRE ATT&CK ${alert.technique_id}: ${alert.technique} (${alert.tactic})`}
                        >
                          {alert.technique_id} {alert.tactic}
                        </span>
                      )}
                    </td>

                    <td>
                      <span
                        className="severity-pill"
                        style={{ '--severity-color': severity.color }}
                      >
                        {severity.label}
                      </span>
                    </td>

                    <td>
                      <span className="mono">{alert.source_ip}</span>
                      {alert.process && (
                        <span className="row-sub" title="Program that owns this traffic">
                          {alert.process}
                        </span>
                      )}
                      {alert.hostname && (
                        <span className="row-sub row-sub-dim" title={alert.hostname}>
                          {alert.hostname}
                        </span>
                      )}
                    </td>

                    <td>
                      <span
                        className={`origin-tag ${
                          alert.source === 'live' ? 'origin-live' : 'origin-sim'
                        }`}
                      >
                        {alert.source === 'live' ? 'LIVE' : 'SIM'}
                      </span>
                    </td>

                    <td>
                      <ConfidenceMeter value={alert.confidence} />
                    </td>

                    <td className="evidence">{alert.evidence}</td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
