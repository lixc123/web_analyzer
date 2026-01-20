import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface Platform {
  name: string;
  steps: string[];
}

const MobileSetup: React.FC = () => {
  const [platform, setPlatform] = useState<'ios' | 'android'>('ios');
  const [qrCode, setQrCode] = useState('');
  const [instructions, setInstructions] = useState<any>(null);
  const [serverIP, setServerIP] = useState('');
  const [serverPort, setServerPort] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [connectedDevices, setConnectedDevices] = useState<any[]>([]);

  useEffect(() => {
    let isMounted = true;

    const fetchData = async () => {
      try {
        const [qrRes, instRes, ipRes, statusRes, devicesRes] = await Promise.all([
          axios.get('/api/v1/proxy/cert/qrcode'),
          axios.get('/api/v1/proxy/cert/instructions'),
          axios.get('/api/v1/proxy/local-ip'),
          axios.get('/api/v1/proxy/status'),
          axios.get('/api/v1/proxy/devices')
        ]);

        if (isMounted) {
          setQrCode(qrRes.data.qrcode);
          setInstructions(instRes.data);
          setServerIP(ipRes.data.ip);
          setServerPort(statusRes.data.port || '8888');

          const devices = devicesRes.data.devices || [];
          setConnectedDevices(devices);

          // 检查是否有对应平台的设备连接
          const hasDevice = devices.some((d: any) =>
            d.type.toLowerCase() === platform
          );
          setIsConnected(hasDevice);
        }
      } catch (error) {
        if (isMounted) {
          console.error('获取数据失败:', error);
        }
      }
    };

    fetchData();

    // 定期刷新设备连接状态
    const interval = setInterval(fetchData, 5000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [platform]);

  const currentInstructions = instructions?.[platform === 'ios' ? 'ios' : 'android'] || [];

  const getPlatformDevices = () => {
    return connectedDevices.filter(d =>
      d.type.toLowerCase() === platform
    );
  };

  return (
    <div className="mobile-setup">
      <h2>移动端配置向导</h2>

      <div className="platform-selector">
        <button
          className={platform === 'ios' ? 'active' : ''}
          onClick={() => setPlatform('ios')}
        >
          iOS
        </button>
        <button
          className={platform === 'android' ? 'active' : ''}
          onClick={() => setPlatform('android')}
        >
          Android
        </button>
      </div>

      {/* 连接状态指示器 */}
      <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
        <div className="status-indicator">
          <span className={`status-dot ${isConnected ? 'online' : 'offline'}`}></span>
          <span className="status-text">
            {isConnected ? `已连接 ${getPlatformDevices().length} 台设备` : '未检测到设备连接'}
          </span>
        </div>

        {isConnected && (
          <div className="connected-devices">
            {getPlatformDevices().map((device, idx) => (
              <div key={idx} className="device-item">
                {device.model || device.type} - {device.os_version}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="server-info">
        <h3>代理配置信息</h3>
        <div className="info-item">
          <span>服务器:</span>
          <strong>{serverIP}</strong>
        </div>
        <div className="info-item">
          <span>端口:</span>
          <strong>{serverPort}</strong>
        </div>
      </div>

      {qrCode && (
        <div className="qr-code">
          <h3>扫描二维码下载证书</h3>
          <img src={`data:image/png;base64,${qrCode}`} alt="证书下载二维码" />
        </div>
      )}

      <div className="instructions">
        <h3>{platform === 'ios' ? 'iOS' : 'Android'} 配置步骤</h3>
        <ol>
          {currentInstructions.map((step: string, index: number) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      </div>

      <div className="actions">
        <a href="/api/v1/proxy/cert/download" download>
          下载证书文件
        </a>
        <p className="mitm-hint">
          或访问 <a href="http://mitm.it" target="_blank" rel="noopener noreferrer">http://mitm.it</a> 下载证书
        </p>
      </div>
    </div>
  );
};

export default MobileSetup;
