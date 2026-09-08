const formatNumber = (value) => (value ?? 0).toLocaleString('en-US')

/** Three big, readable counters across the top of the dashboard. */
export default function StatCards({ stats, running, connection }) {
  const monitoring = connection === 'live' && running

  return (
    <section className="stat-cards" aria-label="Live counters">
      <div className="stat-card">
        <span className="stat-label">Traffic records analysed</span>
        <span className="stat-value" aria-live="off">
          {formatNumber(stats.flows_processed)}
        </span>
        <span className="stat-note">Read only, never modified</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Threats detected</span>
        <span className="stat-value stat-value-alert">
          {formatNumber(stats.alerts_raised)}
        </span>
        <span className="stat-note">Across all three rules</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Monitoring status</span>
        <span className="stat-value stat-value-status">
          <span
            className={`status-dot ${monitoring ? 'status-dot-live' : 'status-dot-idle'}`}
            aria-hidden="true"
          />
          {connection !== 'live'
            ? 'Disconnected'
            : running
              ? 'Watching'
              : 'Paused'}
        </span>
        <span className="stat-note">
          {connection === 'live'
            ? 'Connected to the traffic feed'
            : 'Reconnecting to the backend...'}
        </span>
      </div>
    </section>
  )
}
