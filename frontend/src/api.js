// Thin REST client.
//
// Backend location comes from two build-time environment variables:
//
//   VITE_API_URL  e.g. https://passive-threat-detector.onrender.com
//   VITE_WS_URL   e.g. wss://passive-threat-detector.onrender.com/ws
//
// Both are OPTIONAL. When unset, requests stay relative to the page origin,
// which is what makes `npm run dev` work through the Vite proxy with no .env
// file at all. In production on Vercel there is no proxy, so VITE_API_URL must
// be set or the browser would look for /api on the Vercel domain and 404.
//
// Vite inlines import.meta.env at BUILD time, not run time. Changing these
// values in the Vercel dashboard therefore requires a redeploy to take effect.

const stripTrailingSlash = (value) => value.replace(/\/+$/, '')

// '' in dev (relative, proxied), absolute origin in production.
export const API_BASE = stripTrailingSlash(
  (import.meta.env.VITE_API_URL || '').trim(),
)

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options)
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      if (body?.detail) detail = body.detail
    } catch {
      // response had no JSON body; keep the status text
    }
    throw new Error(detail)
  }
  return response.json()
}

export const startSimulation = () =>
  request('/api/simulation/start', { method: 'POST' })

export const stopSimulation = () =>
  request('/api/simulation/stop', { method: 'POST' })

export const resetSimulation = () =>
  request('/api/simulation/reset', { method: 'POST' })

export const triggerAttack = (threatType) =>
  request(`/api/attack/${threatType}`, { method: 'POST' })

export const getStatus = () => request('/api/status')

/**
 * URL of the CSV incident report.
 *
 * Returned as a URL rather than fetched, so the browser handles it as a normal
 * download instead of us buffering the whole file in memory just to re-save it.
 */
export const reportCsvUrl = () => `${API_BASE}/api/report.csv`

/**
 * Resolves the WebSocket URL, preferring an explicit override, then the API
 * base, then the page origin.
 *
 * The scheme is never hardcoded. It is always derived, so an https:// page
 * yields wss:// and an http:// page yields ws://. Mixing a wss: page with a
 * ws: socket is blocked by browsers as mixed content, which is exactly the
 * failure this function exists to prevent.
 */
export function websocketUrl() {
  const explicit = stripTrailingSlash(
    (import.meta.env.VITE_WS_URL || '').trim(),
  )
  if (explicit) {
    // Tolerate the origin being supplied without the /ws path.
    return explicit.endsWith('/ws') ? explicit : `${explicit}/ws`
  }

  if (API_BASE) {
    // https -> wss, http -> ws. Order matters: replace the longer scheme first.
    const wsBase = API_BASE.startsWith('https:')
      ? API_BASE.replace(/^https:/, 'wss:')
      : API_BASE.replace(/^http:/, 'ws:')
    return `${wsBase}/ws`
  }

  // Same-origin fallback: dev through the Vite proxy.
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}/ws`
}
