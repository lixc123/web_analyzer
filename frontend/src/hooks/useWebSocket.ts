import { useEffect, useRef, useCallback } from 'react'
import { useGlobalStore } from '@store/GlobalStore'

interface WebSocketMessage {
  type: string
  data?: any
  message?: string
  timestamp?: string
}

export interface LlmChatMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export const useWebSocket = (clientId = 'default-client') => {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5
  const reconnectDelay = 5000

  const { setWsConnected } = useGlobalStore()

  const connect = useCallback(() => {
    if (
      wsRef.current?.readyState === WebSocket.OPEN ||
      wsRef.current?.readyState === WebSocket.CONNECTING
    ) {
      return
    }

    // 清理之前的连接
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    try {
      // 动态获取WebSocket URL - 支持本地和局域网访问
      const getWebSocketURL = () => {
        const hostname = window.location.hostname;
        const port = hostname === 'localhost' || hostname === '127.0.0.1' ? '8000' : '8000';
        const host = hostname === 'localhost' || hostname === '127.0.0.1' ? 'localhost' : hostname;
        return `ws://${host}:${port}/ws/${clientId}`;
      };
      
      const wsUrl = getWebSocketURL()
      console.log('尝试连接WebSocket:', wsUrl)
      const ws = new WebSocket(wsUrl)

      // 设置连接超时
      const connectionTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.warn('WebSocket连接超时，关闭连接')
          ws.close()
        }
      }, 5000)

      ws.onopen = () => {
        clearTimeout(connectionTimeout)
        console.log('WebSocket连接已建立')
        setWsConnected(true)
        reconnectAttempts.current = 0
        
        // 发送ping保持连接
        const pingMessage = { 
          type: 'ping', 
          timestamp: new Date().toISOString() 
        }
        ws.send(JSON.stringify(pingMessage))
      }

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          handleMessage(message)
        } catch (error) {
          console.error('解析WebSocket消息失败:', error, '原始数据:', event.data)
          // 尝试处理非JSON格式的消息
          if (typeof event.data === 'string' && event.data.startsWith('Echo:')) {
            console.warn('收到旧格式的Echo消息，已忽略')
            return
          }
        }
      }

      ws.onclose = (event) => {
        clearTimeout(connectionTimeout)
        console.log('WebSocket连接已关闭:', event.code, event.reason || '无原因')
        setWsConnected(false)
        wsRef.current = null

        // 更严格的重连条件：只在特定错误码时重连
        const shouldReconnect = (
          event.code !== 1000 && // 正常关闭
          event.code !== 1001 && // 页面离开
          event.code !== 1005 && // 没有状态码
          event.code !== 4000 && // 自定义关闭
          reconnectAttempts.current < maxReconnectAttempts
        )

        if (shouldReconnect) {
          reconnectAttempts.current++
          const delay = Math.min(reconnectDelay + (reconnectAttempts.current * 3000), 30000) // 最大30秒延迟
          console.log(`尝试重连 (${reconnectAttempts.current}/${maxReconnectAttempts}) 延迟${delay}ms...`)
          
          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect()
          }, delay)
        } else if (event.code !== 1000 && event.code !== 1001) {
          console.warn('WebSocket重连失败，已达到最大重试次数或不需要重连')
        }
      }

      ws.onerror = (error) => {
        clearTimeout(connectionTimeout)
        console.error('WebSocket错误:', error)
        setWsConnected(false)
      }

      wsRef.current = ws
    } catch (error) {
      console.error('创建WebSocket连接失败:', error)
      setWsConnected(false)
    }
  }, [clientId, setWsConnected])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.close(1000, '手动断开连接')
      wsRef.current = null
    }
    
    setWsConnected(false)
  }, [setWsConnected])

  const sendMessage = useCallback((message: WebSocketMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify(message))
        return true
      } catch (error) {
        console.error('发送WebSocket消息失败:', error)
        return false
      }
    } else {
      // 只在连接状态不是CONNECTING时才警告
      if (wsRef.current?.readyState !== WebSocket.CONNECTING) {
        console.warn('WebSocket未连接，无法发送消息')
      }
      return false
    }
  }, [])

  const toLlmContext = useCallback((messages: any[]): LlmChatMessage[] => {
    return (messages || [])
      .filter((m) => m && typeof m.content === 'string')
      .map((m) => {
        if (m.type === 'user') {
          return { role: 'user', content: m.content }
        }
        if (m.type === 'assistant') {
          return { role: 'assistant', content: m.content }
        }
        return { role: 'assistant', content: m.content }
      })
  }, [])

  const handleMessage = useCallback((message: WebSocketMessage) => {
    switch (message.type) {
      case 'crawler_progress':
        // 触发爬虫进度更新事件
        window.dispatchEvent(new CustomEvent('crawler-progress', { 
          detail: message.data 
        }))
        break
        
      case 'analysis_result':
        // 触发分析结果更新事件
        window.dispatchEvent(new CustomEvent('analysis-result', { 
          detail: message.data 
        }))
        break
        
      case 'error':
        // 触发错误事件
        window.dispatchEvent(new CustomEvent('ws-error', { 
          detail: { message: message.message, data: message.data }
        }))
        break
        
      case 'ping':
        // 响应ping消息
        sendMessage({ type: 'pong', timestamp: new Date().toISOString() })
        break

      case 'pong':
        break
        
      case 'echo':
      case 'text_message':
        // 处理服务器回声消息，通常用于测试连接
        console.log('收到服务器回声:', message.data)
        break
        
      default:
        console.log('收到未知类型的WebSocket消息:', message.type, message)
    }
  }, [sendMessage])

  // 组件挂载时连接
  useEffect(() => {
    connect()
    
    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  // 页面可见性变化时重连
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) {
          connect()
        }
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [connect])

  return {
    isConnected: wsRef.current?.readyState === WebSocket.OPEN,
    connect,
    disconnect,
    sendMessage,
    toLlmContext,
  }
}
