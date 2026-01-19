import React, { useState } from 'react';
import axios from 'axios';

const CertManager: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleInstallWindows = async () => {
    setLoading(true);
    setMessage('');
    try {
      const res = await axios.post('/api/v1/proxy/cert/install-windows');
      setMessage('证书安装成功！');
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
