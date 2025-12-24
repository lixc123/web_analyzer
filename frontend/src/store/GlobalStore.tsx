import React, { createContext, useContext, ReactNode } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

// 全局状态接口
interface GlobalState {
  // 主题相关
  theme: 'light' | 'dark'
  setTheme: (theme: 'light' | 'dark') => void
  
  // WebSocket连接状态
  wsConnected: boolean
  setWsConnected: (connected: boolean) => void
  
  // 当前活动会话
  currentSession: string | null
  setCurrentSession: (sessionId: string | null) => void
  
  // 侧边栏折叠状态
  sidebarCollapsed: boolean
  setSidebarCollapsed: (collapsed: boolean) => void
  
  // 用户设置
  settings: {
    autoSave: boolean
    notifications: boolean
    maxConcurrentRequests: number
    analysisThreshold: number
  }
  updateSettings: (settings: Partial<GlobalState['settings']>) => void
  
  // 系统状态
  systemStatus: {
    backend: 'healthy' | 'unhealthy' | 'unknown'
  }
  updateSystemStatus: (status: Partial<GlobalState['systemStatus']>) => void
}

// 创建Zustand store
const useGlobalStore = create<GlobalState>()(
  persist(
    (set, get) => ({
      // 主题
      theme: 'light',
      setTheme: (theme) => set({ theme }),
      
      // WebSocket连接状态
      wsConnected: false,
      setWsConnected: (wsConnected) => set({ wsConnected }),
      
      // 当前活动会话
      currentSession: null,
      setCurrentSession: (currentSession) => set({ currentSession }),
      
      // 侧边栏状态
      sidebarCollapsed: false,
      setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
      
      // 用户设置
      settings: {
        autoSave: true,
        notifications: true,
        maxConcurrentRequests: 5,
        analysisThreshold: 4.0,
      },
      updateSettings: (newSettings) => 
        set((state) => ({
          settings: { ...state.settings, ...newSettings }
        })),
      
      // 系统状态
      systemStatus: {
        backend: 'unknown',
      },
      updateSystemStatus: (newStatus) =>
        set((state) => ({
          systemStatus: { ...state.systemStatus, ...newStatus }
        })),
    }),
    {
      name: 'web-analyzer-global-state',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
        settings: state.settings,
      }),
    }
  )
)

// Context for React components
const GlobalContext = createContext<{
  store: typeof useGlobalStore
} | null>(null)

// Provider component
interface GlobalProviderProps {
  children: ReactNode
}

export const GlobalProvider: React.FC<GlobalProviderProps> = ({ children }) => {
  return (
    <GlobalContext.Provider value={{ store: useGlobalStore }}>
      {children}
    </GlobalContext.Provider>
  )
}

// Hook to use the global store
export { useGlobalStore }

// Hook to use the global context
export const useGlobalContext = () => {
  const context = useContext(GlobalContext)
  if (!context) {
    throw new Error('useGlobalContext must be used within a GlobalProvider')
  }
  return context
}

// Selectors for better performance
export const useTheme = () => useGlobalStore((state) => state.theme)
export const useWebSocketStatus = () => useGlobalStore((state) => state.wsConnected)
export const useCurrentSession = () => useGlobalStore((state) => state.currentSession)
export const useSidebarCollapsed = () => useGlobalStore((state) => state.sidebarCollapsed)
export const useSettings = () => useGlobalStore((state) => state.settings)
export const useSystemStatus = () => useGlobalStore((state) => state.systemStatus)
