import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface ProxyConfig {
  host: string;
  port: number;
  enable_system_proxy: boolean;
}

const ProxyControl: React.FC = () => {
  const [config, setConfig] = useState<ProxyConfig>({
    host: '0.0.0.0',
    port: 8888,
    enable_system_proxy: false
  });
  const [isRunning, setIsRunning] = useState(false);
  const [localIP, setLocalIP] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    checkStatus();
    fetchLocalIP();
  }, []);

  const checkStatus = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/status');
      setIsRunning(res.data.running);
    } catch (error) {
      console.error('获取状态失败:', error);
    }
  };

  const fetchLocalIP = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/local-ip');
      setLocalIP(res.data.ip);
    } catch (error) {
      console.error('获取本机IP失败:', error);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/v1/proxy/start', config);
      if (response.status === 200) {
        setIsRunning(true);
        alert('代理服务启动成功');
        // 异步检查状态以确保同步，但不依赖它来更新UI
        checkStatus();
      }
    } catch (error) {
      alert('启动失败: ' + (error as any).response?.data?.detail);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/v1/proxy/stop');
      if (response.status === 200) {
        setIsRunning(false);
        alert('代理服务已停止');
        // 异步检查状态以确保同步，但不依赖它来更新UI
        checkStatus();
      }
    } catch (error) {
      alert('停止失败: ' + (error as any).response?.data?.detail);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="proxy-control">
      <h2>代理服务控制</h2>

      <div className="status">
        <span>状态: </span>
        <span className={isRunning ? 'running' : 'stopped'}>
          {isRunning ? '运行中' : '已停止'}
        </span>
      </div>

      {localIP && (
        <div className="local-ip">
          <span>本机IP: </span>
          <strong>{localIP}</strong>
        </div>
      )}

      <div className="config-form">
        <div className="form-group">
          <label>端口:</label>
          <input
            type="number"
            min="1"
            max="65535"
            value={config.port}
            onChange={(e) => {
              const port = parseInt(e.target.value);
              if (!isNaN(port) && port >= 1 && port <= 65535) {
                setConfig({...config, port});
              }
            }}
            disabled={isRunning}
          />
        </div>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={config.enable_system_proxy}
              onChange={(e) => setConfig({...config, enable_system_proxy: e.target.checked})}
              disabled={isRunning}
            />
            启用系统代理
          </label>
        </div>
      </div>

      <div className="actions">
        {!isRunning ? (
          <button onClick={handleStart} disabled={loading}>
            {loading ? '启动中...' : '启动代理'}
          </button>
        ) : (
          <button onClick={handleStop} disabled={loading}>
            {loading ? '停止中...' : '停止代理'}
          </button>
        )}
      </div>
    </div>
  );
};

export default ProxyControl;
