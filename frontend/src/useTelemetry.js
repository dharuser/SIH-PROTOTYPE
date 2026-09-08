import { useCallback, useEffect, useReducer, useRef } from 'react'
import { websocketUrl } from './api'

const MAX_ALERTS = 25 // a little more than the 20 the table shows
const MAX_FLOWS = 6 // tiny live ticker

const EMPTY_STATS = {
  running: false,
  flows_processed: 0,
  alerts_raised: 0,
  alerts_by_type: { flood: 0, port_scan: 0, exfiltration: 0 },
  started_at: null,
}

const initialState = {
  connection: 'connecting', // connecting | live | offline
  stats: EMPTY_STATS,
  alerts: [], // newest first
  flows: [], // newest first
  thresholds: null,
  lastScenario: null,
}

let alertSeq = 0
const withKey = (alert) => ({ ...alert, _key: `a${++alertSeq}` })

function reducer(state, action) {
  switch (action.type) {
    case 'connection':
      return { ...state, connection: action.value }

    case 'snapshot': {
      const { stats, alerts = [], flows = [], thresholds } = action.data
      return {
        ...state,
        connection: 'live',
        stats: stats || EMPTY_STATS,
        thresholds: thresholds || null,
        // Backend history is oldest-first; the UI wants newest-first.
        alerts: [...alerts].reverse().slice(0, MAX_ALERTS).map(withKey),
        flows: [...flows].reverse().slice(0, MAX_FLOWS),
      }
    }

    case 'flow':
      return {
        ...state,
        stats: action.stats || state.stats,
        flows: [action.data, ...state.flows].slice(0, MAX_FLOWS),
      }

    case 'alert':
      return {
        ...state,
        stats: action.stats || state.stats,
        alerts: [withKey(action.data), ...state.alerts].slice(0, MAX_ALERTS),
      }

    case 'status':
      return { ...state, stats: action.data }

    case 'reset':
      return {
        ...state,
        stats: action.data,
        alerts: [],
        flows: [],
        lastScenario: null,
      }

    case 'scenario_started':
      return { ...state, lastScenario: { ...action.data, at: Date.now() } }

    default:
      return state
  }
}

/**
 * Opens the backend WebSocket and keeps dashboard state in sync.
 * Reconnects automatically if the backend restarts.
 */
export function useTelemetry() {
  const [state, dispatch] = useReducer(reducer, initialState)
  const socketRef = useRef(null)

  /**
   * Sends a control command back up the open socket.
   *
   * Returns false if the socket isn't ready, so callers can fall back to REST.
   * Preferring the socket matters when the API runs on more than one instance:
   * a REST call may be answered by an instance this browser isn't streaming
   * from, and the resulting alert would never reach this screen.
   */
  const sendCommand = useCallback((command) => {
    const socket = socketRef.current
    if (!socket || socket.readyState !== WebSocket.OPEN) return false
    try {
      socket.send(JSON.stringify(command))
      return true
    } catch {
      return false
    }
  }, [])

  useEffect(() => {
    let closed = false
    let reconnectTimer = null
    let pingTimer = null

    const connect = () => {
      if (closed) return
      dispatch({ type: 'connection', value: 'connecting' })

      const socket = new WebSocket(websocketUrl())
      socketRef.current = socket

      socket.onopen = () => {
        if (closed) return
        dispatch({ type: 'connection', value: 'live' })
        // Keeps the connection warm and surfaces a dead socket quickly.
        pingTimer = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) socket.send('ping')
        }, 25000)
      }

      socket.onmessage = (event) => {
        let message
        try {
          message = JSON.parse(event.data)
        } catch {
          return
        }
        dispatch({
          type: message.type,
          data: message.data,
          stats: message.stats,
        })
      }

      socket.onclose = () => {
        clearInterval(pingTimer)
        if (closed) return
        dispatch({ type: 'connection', value: 'offline' })
        reconnectTimer = setTimeout(connect, 2000)
      }

      socket.onerror = () => {
        // onclose always follows, which is where reconnection is handled.
      }
    }

    connect()

    return () => {
      closed = true
      clearTimeout(reconnectTimer)
      clearInterval(pingTimer)
      socketRef.current?.close()
    }
  }, [])

  return { ...state, sendCommand }
}
