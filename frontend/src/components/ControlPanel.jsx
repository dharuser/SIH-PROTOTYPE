import { THREATS } from '../threats'

/**
 * The demo controls: one big button per attack scenario, plus the
 * start / stop / reset controls for the background traffic simulation.
 */
export default function ControlPanel({
  running,
  busy,
  onTriggerAttack,
  onStart,
  onStop,
  onReset,
}) {
  return (
    <section className="panel controls" aria-labelledby="controls-heading">
      <h2 id="controls-heading" className="panel-title">
        Trigger a threat
      </h2>

      <div className="attack-buttons">
        {THREATS.map((threat) => (
          <button
            key={threat.id}
            type="button"
            className="attack-button"
            style={{ '--accent': threat.color }}
            onClick={() => onTriggerAttack(threat.id)}
            disabled={busy}
          >
            <span className="attack-button-label">{threat.button}</span>
            <span className="attack-button-hint">{threat.plain}</span>
          </button>
        ))}
      </div>

      <div className="sim-controls">
        <span className="sim-label">Background traffic</span>
        <div className="sim-buttons">
          <button
            type="button"
            className="ghost-button"
            onClick={onStart}
            disabled={running}
          >
            Start
          </button>
          <button
            type="button"
            className="ghost-button"
            onClick={onStop}
            disabled={!running}
          >
            Stop
          </button>
          <button type="button" className="ghost-button" onClick={onReset}>
            Reset
          </button>
        </div>
      </div>
    </section>
  )
}
