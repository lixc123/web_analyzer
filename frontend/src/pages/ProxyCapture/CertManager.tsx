import React, { useState, useEffect } from 'react';
import { Card, Button, Alert, Descriptions, Space, message, Modal, Tag } from 'antd';
import {
  SafetyCertificateOutlined,
  DownloadOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  ReloadOutlined,
  SyncOutlined
} from '@ant-design/icons';
import axios from 'axios';

interface CertStatus {
  exists: boolean;
  path: string;
  installed_windows: boolean | null;
  expiry_date?: string;
  days_until_expiry?: number;
  is_expired?: boolean;
  is_expiring_soon?: boolean;
}

interface CertExpiryCheck {
  status: 'valid' | 'expiring_soon' | 'expired' | 'error';
  message: string;
  action?: string;
}

const CertManager: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [certStatus, setCertStatus] = useState<CertStatus | null>(null);
  const [expiryCheck, setExpiryCheck] = useState<CertExpiryCheck | null>(null);
  const [regenerateLoading, setRegenerateLoading] = useState(false);

  useEffect(() => {
    fetchCertStatus();
    checkCertExpiry();
  }, []);

  const fetchCertStatus = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/cert/status');
      setCertStatus(res.data);
    } catch (error) {
      console.error('获取证书状态失败:', error);
      message.error('获取证书状态失败');
    }
  };

  const checkCertExpiry = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/cert/expiry-check');
      setExpiryCheck(res.data);
    } catch (error) {
      console.error('检查证书过期状态失败:', error);
    }
  };

  const handleInstallWindows = async () => {
    setLoading(true);
    try {
      await axios.post('/api/v1/proxy/cert/install-windows');
      message.success('证书安装成功！');
      await fetchCertStatus();
    } catch (error: any) {
      message.error('证书安装失败: ' + (error.response?.data?.detail || '未知错误'));
    } finally {
      setLoading(false);
    }
  };

  const handleUninstallWindows = async () => {
    setLoading(true);
    try {
      await axios.post('/api/v1/proxy/cert/uninstall-windows');
      message.success('证书卸载成功！');
      await fetchCertStatus();
    } catch (error: any) {
      message.error('证书卸载失败: ' + (error.response?.data?.detail || '未知错误'));
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerateCert = () => {
    Modal.confirm({
      title: '确认重新生成证书',
      content: '重新生成证书后，需要重启代理服务并在所有设备上重新安装新证书。确定要继续吗？',
      okText: '确定',
      cancelText: '取消',
      onOk: async () => {
        setRegenerateLoading(true);
        try {
          await axios.post('/api/v1/proxy/cert/regenerate');
          message.success('证书已重新生成，请重启代理服务并重新安装证书');
          await fetchCertStatus();
          await checkCertExpiry();
        } catch (error: any) {
          message.error('重新生成证书失败: ' + (error.response?.data?.detail || '未知错误'));
        } finally {
          setRegenerateLoading(false);
        }
      }
    });
  };

  const getExpiryAlertType = () => {
    if (!expiryCheck) return 'info';
    switch (expiryCheck.status) {
      case 'expired':
        return 'error';
      case 'expiring_soon':
        return 'warning';
      case 'valid':
        return 'success';
      default:
        return 'info';
    }
  };

  const getExpiryIcon = () => {
    if (!expiryCheck) return null;
    switch (expiryCheck.status) {
      case 'expired':
        return <CloseCircleOutlined />;
      case 'expiring_soon':
        return <WarningOutlined />;
      case 'valid':
        return <CheckCircleOutlined />;
      default:
        return null;
    }
  };

  return (
    <Card
      title={
        <Space>
          <SafetyCertificateOutlined />
          <span>证书管理</span>
        </Space>
      }
      extra={
        <Button
          icon={<ReloadOutlined />}
          onClick={() => {
            fetchCertStatus();
            checkCertExpiry();
          }}
          size="small"
        >
          刷新状态
        </Button>
      }
    >
      {/* 证书过期提醒 */}
      {expiryCheck && expiryCheck.status !== 'valid' && (
        <Alert
          message={expiryCheck.message}
          description={expiryCheck.action}
          type={getExpiryAlertType() as any}
          icon={getExpiryIcon()}
          showIcon
          style={{ marginBottom: 16 }}
          action={
            expiryCheck.status === 'expired' || expiryCheck.status === 'expiring_soon' ? (
              <Button
                size="small"
                type="primary"
                danger={expiryCheck.status === 'expired'}
                onClick={handleRegenerateCert}
                loading={regenerateLoading}
                icon={<SyncOutlined />}
              >
                重新生成
              </Button>
            ) : undefined
          }
        />
      )}

      {/* 证书状态信息 */}
      {certStatus && (
        <Descriptions bordered column={2} size="small" style={{ marginBottom: 16 }}>
          <Descriptions.Item label="证书文件" span={2}>
            {certStatus.exists ? (
              <Tag color="success" icon={<CheckCircleOutlined />}>已生成</Tag>
            ) : (
              <Tag color="error" icon={<CloseCircleOutlined />}>未生成</Tag>
            )}
          </Descriptions.Item>
          
          {certStatus.installed_windows !== null && (
            <Descriptions.Item label="Windows系统" span={2}>
              {certStatus.installed_windows ? (
                <Tag color="success" icon={<CheckCircleOutlined />}>已安装</Tag>
              ) : (
                <Tag color="warning" icon={<WarningOutlined />}>未安装</Tag>
              )}
            </Descriptions.Item>
          )}
          
          {certStatus.expiry_date && (
            <>
              <Descriptions.Item label="过期时间" span={2}>
                {new Date(certStatus.expiry_date).toLocaleString('zh-CN')}
              </Descriptions.Item>
              <Descriptions.Item label="剩余天数" span={2}>
                {certStatus.days_until_expiry !== undefined && (
                  <span style={{ 
                    color: certStatus.is_expired ? 'red' : 
                           certStatus.is_expiring_soon ? 'orange' : 'green',
                    fontWeight: 'bold'
                  }}>
                    {certStatus.days_until_expiry} 天
                  </span>
                )}
              </Descriptions.Item>
            </>
          )}
          
          {certStatus.path && (
            <Descriptions.Item label="证书路径" span={2}>
              <code style={{ fontSize: '12px' }}>{certStatus.path}</code>
            </Descriptions.Item>
          )}
        </Descriptions>
      )}

      {/* 说明信息 */}
      <Alert
        message="HTTPS 抓包说明"
        description={
          <div>
            <p>HTTPS 抓包需要安装 CA 证书到系统受信任的根证书存储中。</p>
            <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
              <li><strong>Windows:</strong> 点击下方"Windows 安装证书"按钮（需要管理员权限）</li>
              <li><strong>移动端:</strong> 在"移动端配置"标签页扫码下载并安装证书</li>
              <li><strong>macOS:</strong> 下载证书后添加到钥匙串并设置为"始终信任"</li>
            </ul>
          </div>
        }
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      {/* 操作按钮 */}
      <Space wrap>
        <Button
          type="primary"
          icon={<DownloadOutlined />}
          href="/api/v1/proxy/cert/download"
          download
        >
          下载证书文件
        </Button>

        <Button
          icon={<CheckCircleOutlined />}
          onClick={handleInstallWindows}
          loading={loading}
        >
          Windows 安装证书
        </Button>

        <Button
          danger
          icon={<CloseCircleOutlined />}
          onClick={handleUninstallWindows}
          loading={loading}
        >
          Windows 卸载证书
        </Button>

        <Button
          icon={<SyncOutlined />}
          onClick={handleRegenerateCert}
          loading={regenerateLoading}
        >
          重新生成证书
        </Button>
      </Space>
    </Card>
  );
};

export default CertManager;
