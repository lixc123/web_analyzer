import React, { useState } from 'react';
import { Card, Tree, Button, Space, message } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import type { DataNode } from 'antd/es/tree';

interface StateData {
  framework: string;
  timestamp: number;
  state: any;
}

const StateViewer: React.FC<{ stateData?: StateData }> = ({ stateData }) => {
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>([]);

  const convertToTreeData = (obj: any, parentKey = ''): DataNode[] => {
    if (!obj || typeof obj !== 'object') return [];

    return Object.keys(obj).map((key) => {
      const value = obj[key];
      const nodeKey = parentKey ? `${parentKey}.${key}` : key;

      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return {
          title: `${key}: {...}`,
          key: nodeKey,
          children: convertToTreeData(value, nodeKey)
        };
      } else if (Array.isArray(value)) {
        return {
          title: `${key}: [${value.length} items]`,
          key: nodeKey,
          children: value.map((item, idx) => ({
            title: `[${idx}]: ${JSON.stringify(item)}`,
            key: `${nodeKey}[${idx}]`,
            isLeaf: true
          }))
        };
      } else {
        return {
          title: `${key}: ${JSON.stringify(value)}`,
          key: nodeKey,
          isLeaf: true
        };
      }
    });
  };

  const exportState = () => {
    if (!stateData) return;
    const blob = new Blob([JSON.stringify(stateData.state, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `state_${stateData.framework}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    message.success('状态数据已导出');
  };

  if (!stateData) {
    return <Card title="状态管理数据"><p>暂无状态数据</p></Card>;
  }

  const treeData = convertToTreeData(stateData.state);

  return (
    <Card
      title={`${stateData.framework} 状态快照`}
      extra={
        <Space>
          <Button icon={<DownloadOutlined />} onClick={exportState}>导出</Button>
        </Space>
      }
    >
      <Tree
        treeData={treeData}
        expandedKeys={expandedKeys}
        onExpand={(keys) => setExpandedKeys(keys)}
        defaultExpandAll={false}
      />
    </Card>
  );
};

export default StateViewer;
