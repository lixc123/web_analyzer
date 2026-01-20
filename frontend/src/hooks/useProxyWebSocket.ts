import { useEffect, useState, useCallback } from 'react'

export interface ProxyStatus {
  running: boolean
  port: number
  https_enabled: boolean
  clients_count: number
  total_requests: number
}

export interface ProxyDevice {
  device_id: string
  device_type: string
  device_model?: string
  os_version?: string
  connected_at: string
  request_count: number
}

export interface ProxyRequest {
  request_id: string
  method: string
  url: string
  source: 'browser' | 'desktop' | 'ios' | 'android'
  device_id?: string
  timestamp: string
  status_code?: number
}

export const useProxyWebSocket = () => {
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus | null>(null)
  const [devices, setDevices] = useState<ProxyDevice[]>([])
  const [recentRequests, setRecentRequests] = useState<ProxyRequest[]>([])

  // 监听代理状态更新
  useEffect(() => {
    const handleProxyStatus = (event: CustomEvent) => {
      setProxyStatus(event.detail)
    }

    window.addEventListener('proxy-status' as any, handleProxyStatus)
    return () => {
      window.removeEventListener('proxy-status' as any, handleProxyStatus)
    }
  }, [])

  // 监听新请求
  useEffect(() => {
    const handleNewRequest = (event: CustomEvent) => {
      const request = event.detail as ProxyRequest
      setRecentRequests(prev => [request, ...prev].slice(0, 100)) // 保留最近100条
    }

    window.addEventListener('proxy-new-request' as any, handleNewRequest)
    return () => {
      window.removeEventListener('proxy-new-request' as any, handleNewRequest)
    }
  }, [])

  // 监听设备连接
  useEffect(() => {
    const handleDeviceConnected = (event: CustomEvent) => {
      const device = event.detail as ProxyDevice
      setDevices(prev => {
        const exists = prev.find(d => d.device_id === device.device_id)
        if (exists) {
          return prev.map(d => d.device_id === device.device_id ? device : d)
        }
        return [...prev, device]
      })
    }

    const handleDeviceDisconnected = (event: CustomEvent) => {
      const deviceId = event.detail.device_id
      setDevices(prev => prev.filter(d => d.device_id !== deviceId))
    }

    window.addEventListener('proxy-device-connected' as any, handleDeviceConnected)
    window.addEventListener('proxy-device-disconnected' as any, handleDeviceDisconnected)

    return () => {
      window.removeEventListener('proxy-device-connected' as any, handleDeviceConnected)
      window.removeEventListener('proxy-device-disconnected' as any, handleDeviceDisconnected)
    }
  }, [])

  const clearRequests = useCallback(() => {
    setRecentRequests([])
  }, [])

  return {
    proxyStatus,
    devices,
    recentRequests,
    clearRequests
  }
}
