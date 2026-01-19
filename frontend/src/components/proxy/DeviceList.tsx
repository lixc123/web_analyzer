import React, { useEffect, useState } from 'react';
import axios from 'axios';

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<any[]>([]);

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const res = await axios.get('/api/v1/proxy/devices');
        setDevices(res.data.devices || []);
      } catch (err) {
        console.error('获取设备列表失败:', err);
      }
    };

    fetchDevices();
    const timer = setInterval(fetchDevices, 5000);
    return () => clearInterval(timer);
  }, []);

  const getDeviceIcon = (type: string) => {
    const icons: any = {
      ios: '📱',
      android: '🤖',
      windows: '💻',
      macos: '🖥️',
      linux: '🐧'
    };
    return icons[type.toLowerCase()] || '📱';
  };

  return (
    <div className="device-list">
      <h3>已连接设备 ({devices.length})</h3>
      {devices.length === 0 ? (
        <p>暂无设备连接</p>
      ) : (
        <ul>
          {devices.map((device, idx) => (
            <li key={idx}>
              <span className="device-icon">{getDeviceIcon(device.type)}</span>
              <div className="device-info">
                <div><strong>{device.type}</strong> {device.model || ''}</div>
                <div>系统: {device.os_version || 'Unknown'}</div>
                <div>首次连接: {new Date(device.first_seen).toLocaleString()}</div>
                <div>请求数: {device.request_count || 0}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default DeviceList;
