import React, { useState } from 'react';
import { Card, Table, Tag, Input, Select, Space, Button } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined, DownloadOutlined } from '@ant-design/icons';

interface WebSocketMessage {
  id: string;
  direction: 'send' | 'receive';
  timestamp: number;
  data: string;
  type: string;
  connection: string;
}

const WebSocketViewer: React.FC<{ messages?: WebSocketMessage[] }> = ({ messages = [] }) => {
  const [searchText, setSearchText] = useState('');
  const [directionFilter, setDirectionFilter] = useState<string>('all');

  const filteredMessages = messages.filter(msg => {
    const matchSearch = msg.data.toLowerCase().includes(searchText.toLowerCase());
    const matchDirection = directionFilter === 'all' || msg.direction === directionFilter;
    return matchSearch && matchDirection;
  });

  const columns = [
    {
      title: '方向',
      dataIndex: 'direction',
      key: 'direction',
      width: 80,
      render: (dir: string) => (
        dir === 'send' ? (
          <Tag icon={<ArrowUpOutlined />} color="blue">发送</Tag>
        ) : (
          <Tag icon={<ArrowDownOutlined />} color="green">接收</Tag>
        )
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
      title: '连接',
      dataIndex: 'connection',
      key: 'connection',
      width: 150,
      ellipsis: true
    },
    {
      title: '消息内容',
      dataIndex: 'data',
      key: 'data',
      ellipsis: true
    }
  ];

  return (
    <Card title="WebSocket 消息">
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Space>
          <Input.Search
            placeholder="搜索消息内容"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            style={{ width: 300 }}
          />
          <Select
            value={directionFilter}
            onChange={setDirectionFilter}
            style={{ width: 120 }}
          >
            <Select.Option value="all">全部</Select.Option>
            <Select.Option value="send">发送</Select.Option>
            <Select.Option value="receive">接收</Select.Option>
          </Select>
          <Button icon={<DownloadOutlined />}>导出</Button>
        </Space>
        <Table
          columns={columns}
          dataSource={filteredMessages}
          rowKey="id"
          pagination={{ pageSize: 20 }}
          size="small"
        />
      </Space>
    </Card>
  );
};

export default WebSocketViewer;
