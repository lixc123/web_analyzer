import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface CertStatus {
  exists: boolean;
  path: string;
  installed_windows: boolean | null;
}

const CertManager: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [certStatus, setCertStatus] = useState<CertStatus | null>(null);

  useEffect(() => {
    fetchCertStatus();
  }, []);

  const fetchCertStatus = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/cert/status');
      setCertStatus(res.data);
    } catch (error) {
      console.error('获取证书状态失败:', error);
    }
  };

  const handleInstallWindows = async () => {
    setLoading(true);
    setMessage('');
    try {
      const res = await axios.post('/api/v1/proxy/cert/install-windows');
      setMessage('证书安装成功！');
      await fetchCertStatus(); // 刷新状态
    } catch (error) {
      setMessage('证书安装失败: ' + (error as any).response?.data?.detail);
    } finally {
      setLoading(false);
    }
  };

  const handleUninstallWindows = async () => {
    setLoading(true);
    setMessage('');
    try {
      const res = await axios.post('/api/v1/proxy/cert/uninstall-windows');
      setMessage('证书卸载成功！');
      await fetchCertStatus(); // 刷新状态
    } catch (error) {
      setMessage('证书卸载失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cert-manager">
      <h2>证书管理</h2>

      <div className="cert-info">
        <p>HTTPS 抓包需要安装 CA 证书到系统受信任的根证书存储中。</p>

        {certStatus && (
          <div className="cert-status">
            <div className="status-item">
              <span>证书文件:</span>
              <strong className={certStatus.exists ? 'status-ok' : 'status-error'}>
                {certStatus.exists ? '已生成' : '未生成'}
              </strong>
            </div>
            {certStatus.installed_windows !== null && (
              <div className="status-item">
                <span>Windows系统:</span>
                <strong className={certStatus.installed_windows ? 'status-ok' : 'status-warning'}>
                  {certStatus.installed_windows ? '已安装' : '未安装'}
                </strong>
              </div>
            )}
            {certStatus.path && (
              <div className="status-item">
                <span>证书路径:</span>
                <code>{certStatus.path}</code>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="actions">
        <a href="/api/v1/proxy/cert/download" download className="btn-download">
          下载证书文件
        </a>

        <button onClick={handleInstallWindows} disabled={loading}>
          {loading ? '安装中...' : 'Windows 安装证书'}
        </button>

        <button onClick={handleUninstallWindows} disabled={loading} className="btn-danger">
          {loading ? '卸载中...' : 'Windows 卸载证书'}
        </button>
      </div>

      {message && (
        <div className={message.includes('成功') ? 'message success' : 'message error'}>
          {message}
        </div>
      )}

      <div className="instructions">
        <h3>安装说明</h3>
        <ul>
          <li>Windows: 点击上方"Windows 安装证书"按钮自动安装</li>
          <li>macOS: 下载证书后双击打开，添加到"钥匙串访问"并设置为"始终信任"</li>
          <li>移动端: 请使用"移动端配置向导"进行配置</li>
        </ul>
      </div>
    </div>
  );
};

export default CertManager;
