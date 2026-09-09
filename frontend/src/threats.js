// Shared, single source of truth for how each threat type is presented.
// The `id` values match the backend's threat_type strings exactly.

export const THREATS = [
  {
    id: 'flood',
    label: 'Flood Attack',
    short: 'Flood',
    color: '#ef4444', // red
    plain: 'Huge numbers of machines hitting one server at once',
    button: 'Simulate Flood Attack',
  },
  {
    id: 'port_scan',
    label: 'Port Scan',
    short: 'Scan',
    color: '#f59e0b', // orange
    plain: 'One machine checking many doors on a server, looking for a way in',
    button: 'Simulate Port Scan',
  },
  {
    id: 'exfiltration',
    label: 'Data Exfiltration',
    short: 'Exfiltration',
    color: '#a855f7', // purple
    plain: 'Far more data leaving the network than coming in',
    button: 'Simulate Data Exfiltration',
  },
  {
    id: 'beaconing',
    label: 'C2 Beaconing',
    short: 'Beaconing',
    color: '#6366f1', // indigo
    plain: 'A machine calling the same address on a timer, like malware reporting in',
    button: 'Simulate C2 Beaconing',
  },
]

// Severity presentation. Ordered most to least urgent.
export const SEVERITIES = {
  critical: { label: 'CRITICAL', color: '#f43f5e' },
  high: { label: 'HIGH', color: '#f97316' },
  medium: { label: 'MEDIUM', color: '#eab308' },
}

export function severityMeta(id) {
  return SEVERITIES[id] || { label: (id || 'UNKNOWN').toUpperCase(), color: '#64748b' }
}

export const THREATS_BY_ID = Object.fromEntries(
  THREATS.map((threat) => [threat.id, threat]),
)

export function threatMeta(id) {
  return (
    THREATS_BY_ID[id] || {
      id,
      label: id,
      short: id,
      color: '#64748b',
      plain: '',
    }
  )
}
