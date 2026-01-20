import React, { useEffect, useState } from 'react';
import axios from 'axios';

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<any[]>([]);
  const [filteredDevices, setFilteredDevices] = useState<any[]>([]);
  const [platformFilter, setPlatformFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

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

  useEffect(() => {
    let filtered = devices;

    // 按平台过滤
    if (platformFilter !== 'all') {
      filtered = filtered.filter(device => {
        const type = device.type.toLowerCase();
        if (platformFilter === 'mobile') {
          return type === 'ios' || type === 'android';
        } else if (platformFilter === 'desktop') {
          return type === 'windows' || type === 'macos' || type === 'linux';
        }
        return type === platformFilter;
      });
    }

    // 按连接状态过滤
    if (statusFilter !== 'all') {
      filtered = filtered.filter(device => {
        const lastSeen = new Date(device.last_seen || device.first_seen);
        const now = new Date();
        const diffMinutes = (now.getTime() - lastSeen.getTime()) / 1000 / 60;

        if (statusFilter === 'online') {
          return diffMinutes < 5; // 5分钟内活跃视为在线
        } else if (statusFilter === 'offline') {
          return diffMinutes >= 5;
        }
        return true;
      });
    }

    setFilteredDevices(filtered);
  }, [devices, platformFilter, statusFilter]);

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

  const isDeviceOnline = (device: any) => {
    const lastSeen = new Date(device.last_seen || device.first_seen);
    const now = new Date();
    const diffMinutes = (now.getTime() - lastSeen.getTime()) / 1000 / 60;
    return diffMinutes < 5;
  };

  return (
    <div className="device-list">
      <div className="device-list-header">
        <h3>已连接设备 ({filteredDevices.length}/{devices.length})</h3>

        <div className="device-filters">
          <select
            value={platformFilter}
            onChange={(e) => setPlatformFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">全部平台</option>
            <option value="mobile">移动端</option>
            <option value="desktop">桌面端</option>
            <option value="ios">iOS</option>
            <option value="android">Android</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">全部状态</option>
            <option value="online">在线</option>
            <option value="offline">离线</option>
          </select>
        </div>
      </div>

      {filteredDevices.length === 0 ? (
        <p>暂无设备连接</p>
      ) : (
        <ul>
          {filteredDevices.map((device, idx) => (
            <li key={idx} className={isDeviceOnline(device) ? 'device-online' : 'device-offline'}>
              <span className="device-icon">{getDeviceIcon(device.type)}</span>
              <div className="device-info">
                <div>
                  <strong>{device.type}</strong> {device.model || ''}
                  <span className={`status-badge ${isDeviceOnline(device) ? 'online' : 'offline'}`}>
                    {isDeviceOnline(device) ? '在线' : '离线'}
                  </span>
                </div>
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
