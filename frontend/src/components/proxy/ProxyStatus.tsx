import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface ProxyStatusProps {
  refreshInterval?: number;
}

const ProxyStatus: React.FC<ProxyStatusProps> = ({ refreshInterval = 3000 }) => {
  const [status, setStatus] = useState<any>(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await axios.get('/api/v1/proxy/status');
        setStatus(res.data);
      } catch (err) {
        console.error('获取状态失败:', err);
      }
    };

    fetchStatus();
    const timer = setInterval(fetchStatus, refreshInterval);
    return () => clearInterval(timer);
  }, [refreshInterval]);

  if (!status) return <div>加载中...</div>;

  return (
    <div className="proxy-status">
      <div className="status-item">
        <span className={`indicator ${status.running ? 'running' : 'stopped'}`}></span>
        <span>{status.running ? '运行中' : '已停止'}</span>
      </div>
      <div className="status-item">
        <span>连接设备: {status.statistics?.devices_count || 0}</span>
      </div>
      <div className="status-item">
        <span>总请求数: {status.statistics?.total_requests || 0}</span>
      </div>
      <div className="status-item">
        <span>系统代理: {status.system_proxy_enabled ? '已启用' : '未启用'}</span>
      </div>
    </div>
  );
};

export default ProxyStatus;
