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

  useEffect(() => {
    let isMounted = true;

    const fetchData = async () => {
      try {
        const [qrRes, instRes, ipRes, statusRes] = await Promise.all([
          axios.get('/api/v1/proxy/cert/qrcode'),
          axios.get('/api/v1/proxy/cert/instructions'),
          axios.get('/api/v1/proxy/local-ip'),
          axios.get('/api/v1/proxy/status')
        ]);

        if (isMounted) {
          setQrCode(qrRes.data.qrcode);
          setInstructions(instRes.data);
          setServerIP(ipRes.data.ip);
          setServerPort(statusRes.data.port || '8888');
        }
      } catch (error) {
        if (isMounted) {
          console.error('获取数据失败:', error);
        }
      }
    };

    fetchData();

    return () => {
      isMounted = false;
    };
  }, []);

  const currentInstructions = instructions?.[platform === 'ios' ? 'ios' : 'android'] || [];

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
      </div>
    </div>
  );
};

export default MobileSetup;
