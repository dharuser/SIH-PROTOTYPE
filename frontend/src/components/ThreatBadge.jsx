import { threatMeta } from '../threats'

/** Colour-coded pill naming the threat type. Red / orange / purple. */
export default function ThreatBadge({ threatType }) {
  const meta = threatMeta(threatType)
  return (
    <span
      className="badge"
      style={{ '--badge-color': meta.color }}
      title={meta.plain}
    >
      {meta.label}
    </span>
  )
}
