import { useCallback, useEffect, useRef, useState } from 'react'

export interface ProxyStatus {
  running: boolean
  host?: string
  port?: number
  system_proxy_enabled?: boolean
  winhttp_proxy_enabled?: boolean
  proxy_session_id?: string
  clients_count?: number
  total_requests?: number
}

// NOTE: The backend does not currently push device connect/disconnect events over WS.
// Keep the type for future use and potential polling.
export interface ProxyDevice {
  device_id: string
  device_type: string
  device_model?: string
  os_version?: string
  connected_at: string
  request_count: number
}

export interface ProxyRequest {
  id: string
  method: string
  url: string
  source: 'web_browser' | 'desktop_app' | 'mobile_ios' | 'mobile_android'
  device?: any
  device_info?: any
  proxy_session_id?: string
  timestamp: number
  status_code?: number
  response_time?: number
  response_size?: number
}

export interface ProxyWebSocketEvent {
  id: string
  connection_id: string
  url?: string
  timestamp?: number | string
  proxy_session_id?: string
  event?: string // ws_start/ws_end
  direction?: 'send' | 'receive'
  is_text?: boolean
  size?: number
  data?: string
  data_artifact?: any
}

export interface ProxyJsEvent {
  id: string
  event_type?: string
  timestamp?: number
  timestamp_ms?: number
  url?: string
  method?: string
  correlated_request_id?: string
  proxy_session_id?: string
  target?: any
  stack?: string
  data?: any
}

export const useProxyWebSocket = () => {
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus | null>(null)
  const [devices] = useState<ProxyDevice[]>([])
  const [recentRequests, setRecentRequests] = useState<ProxyRequest[]>([])
  const [websocketEvents, setWebsocketEvents] = useState<ProxyWebSocketEvent[]>([])
  const [jsEvents, setJsEvents] = useState<ProxyJsEvent[]>([])

  const wsRef = useRef<WebSocket | null>(null)
  const stoppedRef = useRef(false)
  const pingTimerRef = useRef<number | null>(null)
  const reconnectTimerRef = useRef<number | null>(null)
  const reconnectAttemptsRef = useRef(0)

  const clearRequests = useCallback(() => {
    setRecentRequests([])
  }, [])

  useEffect(() => {
    stoppedRef.current = false

    const getProxyWsUrl = () => {
      const envBaseURL = import.meta.env.VITE_WS_BASE_URL
      if (envBaseURL) return `${envBaseURL}/ws/proxy-events`

      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      return `${protocol}://${window.location.host}/ws/proxy-events`
    }

    const normalizeRequest = (raw: any): ProxyRequest => {
      const deviceInfo = raw?.device_info ?? raw?.device

      let source = raw?.source as ProxyRequest['source'] | undefined
      const platform = deviceInfo?.platform
      if (!source && platform) {
        if (platform === 'iOS') source = 'mobile_ios'
        else if (platform === 'Android') source = 'mobile_android'
        else if (['Windows', 'macOS', 'Linux'].includes(platform)) source = 'desktop_app'
        else source = 'web_browser'
      }
      if (!source) source = 'web_browser'

      return {
        ...raw,
        id: String(raw?.id ?? raw?.request_id ?? ''),
        device: raw?.device,
        device_info: deviceInfo,
        source,
        proxy_session_id: raw?.proxy_session_id ?? raw?.proxy_session ?? undefined,
        timestamp: Number(raw?.timestamp ?? Date.now() / 1000),
      }
    }

    function scheduleReconnect() {
      if (stoppedRef.current) return
      reconnectAttemptsRef.current += 1
      const delay = Math.min(1000 * reconnectAttemptsRef.current, 15000)
      reconnectTimerRef.current = window.setTimeout(connect, delay)
    }

    function cleanupTimers() {
      if (pingTimerRef.current) {
        clearInterval(pingTimerRef.current)
        pingTimerRef.current = null
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
    }

    function connect() {
      if (stoppedRef.current) return

      const current = wsRef.current
      if (current && (current.readyState === WebSocket.OPEN || current.readyState === WebSocket.CONNECTING)) {
        return
      }

      const ws = new WebSocket(getProxyWsUrl())
      wsRef.current = ws

      ws.onopen = () => {
        reconnectAttemptsRef.current = 0

        // Keepalive ping (backend responds with pong).
        pingTimerRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }))
          }
        }, 30000)
      }

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          const type = message?.type
          const data = message?.data

          if (type === 'proxy_status') {
            setProxyStatus(data)
            return
          }

          if (type === 'new_request') {
            const request = normalizeRequest(data)
            if (!request.id) return
            setRecentRequests((prev) => [request, ...prev].slice(0, 100))
            return
          }

          if (type === 'new_response') {
            const requestId = data?.request_id
            if (!requestId) return
            setRecentRequests((prev) =>
              prev.map((r) =>
                r.id === requestId
                  ? {
                      ...r,
                      status_code: data?.status_code ?? r.status_code,
                      response_time: data?.response_time ?? r.response_time,
                      response_size: data?.content_length ?? r.response_size,
                    }
                  : r
              )
            )
            return
          }

          if (type === 'websocket_event') {
            const evt = data as ProxyWebSocketEvent
            if (!evt?.connection_id) return
            setWebsocketEvents((prev) => [evt, ...prev].slice(0, 300))
            return
          }

          if (type === 'js_event') {
            const evt = data as ProxyJsEvent
            if (!evt?.id) return
            setJsEvents((prev) => [evt, ...prev].slice(0, 500))
            return
          }
        } catch {
          // ignore non-JSON messages
        }
      }

      ws.onclose = () => {
        cleanupTimers()
        wsRef.current = null
        scheduleReconnect()
      }

      ws.onerror = () => {
        // onclose handles cleanup/reconnect
      }
    }

    connect()

    return () => {
      stoppedRef.current = true
      cleanupTimers()
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [])

  return {
    proxyStatus,
    devices,
    recentRequests,
    clearRequests,
    websocketEvents,
    jsEvents,
  }
}
