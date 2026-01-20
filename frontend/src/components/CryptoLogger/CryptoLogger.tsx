import React, { useState } from 'react';
import { Card, Table, Tag, Select, Space } from 'antd';
import { LockOutlined, UnlockOutlined, SafetyOutlined } from '@ant-design/icons';

interface CryptoOperation {
  id: string;
  operation: 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'digest';
  algorithm: string;
  timestamp: number;
  dataSize: number;
  resultPreview?: string;
}

const CryptoLogger: React.FC<{ operations?: CryptoOperation[] }> = ({ operations = [] }) => {
  const [operationFilter, setOperationFilter] = useState<string>('all');

  const filteredOps = operations.filter(op =>
    operationFilter === 'all' || op.operation === operationFilter
  );

  const getOperationIcon = (op: string) => {
    switch (op) {
      case 'encrypt': return <LockOutlined />;
      case 'decrypt': return <UnlockOutlined />;
      default: return <SafetyOutlined />;
    }
  };

  const columns = [
    {
      title: '操作',
      dataIndex: 'operation',
      key: 'operation',
      width: 100,
      render: (op: string) => (
        <Tag icon={getOperationIcon(op)} color="blue">
          {op.toUpperCase()}
        </Tag>
      )
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 100,
      render: (ts: number) => new Date(ts).toLocaleTimeString()
    },
    {
      title: '算法',
      dataIndex: 'algorithm',
      key: 'algorithm',
      width: 150
    },
    {
      title: '数据大小',
      dataIndex: 'dataSize',
      key: 'dataSize',
      width: 100,
      render: (size: number) => `${size} bytes`
    },
    {
      title: '结果预览',
      dataIndex: 'resultPreview',
      key: 'resultPreview',
      ellipsis: true
    }
  ];

  return (
    <Card title="Crypto 操作日志">
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Select
          value={operationFilter}
          onChange={setOperationFilter}
          style={{ width: 150 }}
        >
          <Select.Option value="all">全部操作</Select.Option>
          <Select.Option value="encrypt">加密</Select.Option>
          <Select.Option value="decrypt">解密</Select.Option>
          <Select.Option value="sign">签名</Select.Option>
          <Select.Option value="verify">验证</Select.Option>
          <Select.Option value="digest">摘要</Select.Option>
        </Select>
        <Table
          columns={columns}
          dataSource={filteredOps}
          rowKey="id"
          pagination={{ pageSize: 20 }}
          size="small"
        />
      </Space>
    </Card>
  );
};

export default CryptoLogger;
