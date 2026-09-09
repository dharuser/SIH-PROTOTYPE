function formatBytes(value) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(0)} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * A short window into the raw feed. Its only job is to make the "we are
 * passively reading traffic" claim visible rather than abstract.
 */
export default function FlowTicker({ flows }) {
  return (
    <section className="panel ticker-panel" aria-labelledby="ticker-heading">
      <h2 id="ticker-heading" className="panel-title">
        Traffic being observed
      </h2>

      {flows.length === 0 ? (
        <p className="ticker-empty">
          Waiting for traffic. Press Start to begin the background feed.
        </p>
      ) : (
        <ul className="ticker">
          {flows.map((flow, index) => (
            <li
              key={`${flow.timestamp}-${flow.source_ip}-${flow.dest_port}-${index}`}
              className="ticker-row mono"
            >
              <span className="ticker-ip">{flow.source_ip}</span>
              <span className="ticker-arrow" aria-hidden="true">
                &rarr;
              </span>
              <span className="ticker-ip">
                {flow.dest_ip}:{flow.dest_port}
              </span>
              <span className="ticker-bytes">
                {flow.source === 'live' && (
                  <span className="ticker-live" title="Captured from a real interface">
                    LIVE
                  </span>
                )}
                in {formatBytes(flow.bytes_in)} / out{' '}
                {formatBytes(flow.bytes_out)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
