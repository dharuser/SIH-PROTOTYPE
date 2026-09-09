const formatNumber = (value) => (value ?? 0).toLocaleString('en-US')

function formatRate(bytesPerSecond) {
  const value = bytesPerSecond ?? 0
  if (value < 1024) return `${value} B/s`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(0)} KB/s`
  return `${(value / (1024 * 1024)).toFixed(1)} MB/s`
}

/**
 * Shows where the analysed traffic is actually coming from.
 *
 * This exists to answer the obvious challenge: "is this real data?" The counts
 * are kept separately for captured and generated traffic so the split is
 * visible rather than asserted.
 */
export default function SourcePanel({ stats }) {
  const live = stats.live_flows ?? 0
  const simulated = stats.simulated_flows ?? 0
  const connected = Boolean(stats.sensor_connected)
  const throughput = stats.sensor_throughput

  return (
    <section className="panel source-panel" aria-labelledby="source-heading">
      <div className="panel-header">
        <h2 id="source-heading" className="panel-title">
          Data source
        </h2>
        <span className={`source-pill ${connected ? 'source-pill-live' : 'source-pill-sim'}`}>
          <span className="status-dot" aria-hidden="true" />
          {connected ? 'LIVE CAPTURE' : 'SIMULATED'}
        </span>
      </div>

      <div className="source-split">
        <div className="source-metric">
          <span className="source-metric-value source-metric-live">
            {formatNumber(live)}
          </span>
          <span className="source-metric-label">Real captured flows</span>
        </div>
        <div className="source-metric">
          <span className="source-metric-value">{formatNumber(simulated)}</span>
          <span className="source-metric-label">Simulated flows</span>
        </div>
      </div>

      {connected ? (
        <dl className="source-meta">
          <div>
            <dt>Sensor host</dt>
            <dd className="mono">{stats.sensor_host || 'unknown'}</dd>
          </div>
          <div>
            <dt>Capturing from</dt>
            <dd className="mono">{stats.sensor_interface || 'unknown'}</dd>
          </div>
          {throughput && (
            <div>
              <dt>Interface throughput</dt>
              <dd className="mono">
                {formatRate(throughput.bytes_recv_per_sec)} in /{' '}
                {formatRate(throughput.bytes_sent_per_sec)} out
              </dd>
            </div>
          )}
        </dl>
      ) : (
        <p className="source-hint">
          No capture sensor connected. Run the sensor agent to analyse real
          packets from a network interface. The detection rules are identical
          either way.
        </p>
      )}
    </section>
  )
}
