import React, { useState } from 'react';
import { Modal, Button, Alert, Typography } from 'antd';
import { UserOutlined } from '@ant-design/icons';
import { useAuth, AuthType } from './AuthProvider';

const { Title, Text } = Typography;

interface LoginModalProps {
  visible: boolean;
  onClose: () => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ visible, onClose }) => {
  const { login } = useAuth();
  const [loading, setLoading] = useState(false);

  // 游客模式登录
  const handleGuestLogin = async () => {
    setLoading(true);
    try {
      const success = await login(AuthType.GUEST);
      if (success) {
        onClose();
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      title="欢迎使用 Web Analyzer"
      open={visible}
      onCancel={onClose}
      footer={null}
      width={400}
      centered
    >
      <div style={{ padding: '20px 0', textAlign: 'center' }}>
        <Alert
          title="网络流量分析平台"
          description="AI功能已移除，专注于网络流量录制和分析"
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
        
        <div style={{ marginBottom: 24 }}>
          <Title level={4}>
            <UserOutlined style={{ color: '#52c41a' }} /> 访客模式
          </Title>
          <Text type="secondary">
            无需注册，立即开始使用网络流量分析功能
          </Text>
        </div>

        <Button
          type="primary"
          size="large"
          icon={<UserOutlined />}
          loading={loading}
          onClick={handleGuestLogin}
          block
        >
          以访客身份进入
        </Button>

        <div style={{ fontSize: '12px', color: '#666', marginTop: 16 }}>
          • 完整的网络流量录制功能<br/>
          • 数据分析和可视化<br/>
          • 会话管理和导出功能
        </div>
      </div>
    </Modal>
  );
};

export default LoginModal;
