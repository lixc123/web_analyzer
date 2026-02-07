import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { message } from 'antd';

// 认证类型枚举 - AI功能已移除，仅保留访客模式
export enum AuthType {
  GUEST = 'guest'
}

// 认证状态接口
export interface AuthState {
  isAuthenticated: boolean;
  authType: AuthType | null;
  sessionId?: string;
  user: {
    id?: string;
    name?: string;
    email?: string;
    tier?: string;
  } | null;
  apiConfig: {
    apiKey?: string;
    baseUrl?: string;
    model?: string;
  } | null;
  quota: {
    used: number;
    limit: number;
    resetTime?: string;
  } | null;
}

// 认证操作接口
export interface AuthActions {
  login: (authType: AuthType, config?: any) => Promise<boolean>;
  logout: () => Promise<void>;
  switchAuth: (newAuthType: AuthType, config?: any) => Promise<boolean>;
  refreshAuth: () => Promise<boolean>;
  updateApiConfig: (config: any) => Promise<boolean>;
}

// 上下文类型
export interface AuthContextType extends AuthState, AuthActions {}

// 创建认证上下文
const AuthContext = createContext<AuthContextType | null>(null);

// 认证Provider组件
export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    authType: null,
    sessionId: undefined,
    user: null,
    apiConfig: null,
    quota: null,
  });

  // 从localStorage加载认证状态
  useEffect(() => {
    const loadAuthState = async () => {
      try {
        const savedAuth = localStorage.getItem('auth_state');
        if (savedAuth) {
          const parsed = JSON.parse(savedAuth);
          setAuthState(prev => ({ ...prev, ...parsed }));
          
          // 验证已保存的认证状态（如果有sessionId）
          const sessionId = parsed?.sessionId;
          if (sessionId) {
            const response = await fetch(`/api/v1/auth/status?session_id=${encodeURIComponent(sessionId)}`, {
              method: 'GET',
              headers: { 'Content-Type': 'application/json' },
            });

            if (response.ok) {
              const data = await response.json();

              if (data.isAuthenticated) {
                const newState: AuthState = {
                  isAuthenticated: true,
                  authType: data.authType,
                  sessionId: sessionId,
                  user: data.user,
                  apiConfig: data.apiConfig,
                  quota: data.quota,
                };

                setAuthState(newState);
                saveAuthState(newState);
              }
            }
          }
        }
      } catch (error) {
        console.error('加载认证状态失败:', error);
        localStorage.removeItem('auth_state');
      }
    };
    
    loadAuthState();
  }, []);

  // 保存认证状态到localStorage
  const saveAuthState = (state: AuthState) => {
    localStorage.setItem('auth_state', JSON.stringify(state));
  };

  // 登录方法 - AI功能已移除，仅支持访客模式
  const login = async (authType: AuthType, config?: any): Promise<boolean> => {
    if (authType === AuthType.GUEST) {
      const guestState: AuthState = {
        isAuthenticated: true,
        authType: AuthType.GUEST,
        sessionId: undefined,
        user: { name: '游客用户' },
        apiConfig: null,
        quota: { used: 0, limit: 1000 }, // 网络流量分析无需限制
      };
      setAuthState(guestState);
      saveAuthState(guestState);
      message.info('以游客模式登录');
      return true;
    }
    return false;
  };

  // 退出登录
  const logout = async (): Promise<void> => {
    try {
      if (authState.sessionId) {
        await fetch(`/api/v1/auth/logout?session_id=${encodeURIComponent(authState.sessionId)}`, {
          method: 'POST'
        });
      }
      
      const emptyState: AuthState = {
        isAuthenticated: false,
        authType: null,
        sessionId: undefined,
        user: null,
        apiConfig: null,
        quota: null,
      };
      
      setAuthState(emptyState);
      localStorage.removeItem('auth_state');
      message.success('已退出登录');
    } catch (error) {
      message.error(`退出登录失败: ${error}`);
    }
  };

  // 切换认证方式
  const switchAuth = async (newAuthType: AuthType, config?: any): Promise<boolean> => {
    await logout();
    return await login(newAuthType, config);
  };

  // 刷新认证状态 - AI功能已移除，访客模式无需刷新
  const refreshAuth = async (): Promise<boolean> => {
    return authState.isAuthenticated && authState.authType === AuthType.GUEST;
  };

  // 更新API配置 - AI功能已移除，无需API配置
  const updateApiConfig = async (config: any): Promise<boolean> => {
    return false; // AI功能已移除
  };

  const contextValue: AuthContextType = {
    ...authState,
    login,
    logout,
    switchAuth,
    refreshAuth,
    updateApiConfig,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// 使用认证上下文的Hook
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth必须在AuthProvider内部使用');
  }
  return context;
};

export default AuthProvider;
