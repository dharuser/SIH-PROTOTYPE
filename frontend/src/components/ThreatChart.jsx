import { THREATS } from '../threats'

/**
 * Small live bar chart of alert counts per threat type.
 * Hand-rolled with divs so the project needs no charting dependency.
 */
export default function ThreatChart({ countsByType }) {
  const counts = THREATS.map((threat) => ({
    ...threat,
    count: countsByType?.[threat.id] ?? 0,
  }))
  const max = Math.max(1, ...counts.map((entry) => entry.count))

  return (
    <section className="panel chart-panel" aria-labelledby="chart-heading">
      <h2 id="chart-heading" className="panel-title">
        Alerts by threat type
      </h2>

      <div className="chart">
        {counts.map((entry) => {
          const heightPercent = (entry.count / max) * 100
          return (
            <div className="chart-column" key={entry.id}>
              <span className="chart-count">{entry.count}</span>
              <div
                className="chart-track"
                role="img"
                aria-label={`${entry.label}: ${entry.count} alert${entry.count === 1 ? '' : 's'}`}
              >
                <div
                  className="chart-bar"
                  style={{
                    height: `${heightPercent}%`,
                    background: entry.color,
                  }}
                />
              </div>
              <span className="chart-label">{entry.short}</span>
            </div>
          )
        })}
      </div>
    </section>
  )
}
