import React, { useState } from 'react';
import { Card, Tree, Typography, Tag, Space, Button, Modal, Collapse } from 'antd';
import { 
  BugOutlined, 
  FileTextOutlined,
  FunctionOutlined,
  WarningOutlined,
  InfoCircleOutlined 
} from '@ant-design/icons';

const { Title, Text } = Typography;
const { Panel } = Collapse;

interface CallStackFrame {
  id: string;
  function: string;
  file: string;
  line: number;
  column: number;
  source?: string;
  variables?: Record<string, any>;
  isUserCode: boolean;
  executionTime?: number;
}

interface CallStackAnalyzerProps {
  requestId: string;
  callStack?: CallStackFrame[];
  visible: boolean;
  onClose: () => void;
}

export const CallStackAnalyzer: React.FC<CallStackAnalyzerProps> = ({
  requestId,
  callStack,
  visible,
  onClose
}) => {
  const [selectedFrame, setSelectedFrame] = useState<CallStackFrame | null>(null);
  const [expandedKeys, setExpandedKeys] = useState<string[]>([]);

  // 使用传入的调用栈数据或空数据
  const actualCallStack = callStack || [];

  const treeData = actualCallStack.map((frame, index) => ({
    title: (
      <Space>
        <Tag color={frame.isUserCode ? 'blue' : 'default'}>
          {frame.isUserCode ? '用户代码' : '系统代码'}
        </Tag>
        <Text strong>{frame.function}</Text>
        <Text type="secondary">
          {frame.file}:{frame.line}
        </Text>
        {frame.executionTime && (
          <Tag color="green">{frame.executionTime}ms</Tag>
        )}
      </Space>
    ),
    key: frame.id,
    icon: frame.isUserCode ? <FunctionOutlined /> : <FileTextOutlined />,
    children: frame.source ? [{
      title: (
        <pre style={{ 
          margin: 0, 
          padding: 8, 
          background: '#f5f5f5',
          borderRadius: 4,
          fontSize: '12px'
        }}>
          {frame.source}
        </pre>
      ),
      key: `${frame.id}-source`,
      icon: <FileTextOutlined />
    }] : undefined
  }));

  const renderFrameDetails = (frame: CallStackFrame) => (
    <Card size="small" title={`${frame.function} - 详细信息`}>
      <Space orientation="vertical" style={{ width: '100%' }}>
        <div>
          <Text strong>文件位置: </Text>
          <Text code>{frame.file}:{frame.line}:{frame.column}</Text>
        </div>
        
        {frame.executionTime && (
          <div>
            <Text strong>执行时间: </Text>
            <Tag color="green">{frame.executionTime}ms</Tag>
          </div>
        )}

        {frame.variables && (
          <div>
            <Text strong>变量状态:</Text>
            <Card size="small" style={{ marginTop: 8 }}>
              {Object.entries(frame.variables).map(([key, value]) => (
                <div key={key} style={{ marginBottom: 4 }}>
                  <Text code>{key}</Text>: 
                  <Text style={{ marginLeft: 8 }}>
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </Text>
                </div>
              ))}
            </Card>
          </div>
        )}

        {frame.source && (
          <div>
            <Text strong>源代码:</Text>
            <pre style={{ 
              background: '#f5f5f5', 
              padding: 12, 
              borderRadius: 4,
              marginTop: 8,
              overflow: 'auto'
            }}>
              {frame.source}
            </pre>
          </div>
        )}
      </Space>
    </Card>
  );

  const getPerformanceAnalysis = () => {
    if (actualCallStack.length === 0) {
      return (
        <Card size="small" title="性能分析">
          <Text type="secondary">暂无调用栈数据</Text>
        </Card>
      );
    }

    const totalTime = actualCallStack.reduce((sum: number, frame: CallStackFrame) => sum + (frame.executionTime || 0), 0);
    const slowFrames = actualCallStack.filter((frame: CallStackFrame) => (frame.executionTime || 0) > 100);
    
    return (
      <Card size="small" title="性能分析">
        <Space orientation="vertical" style={{ width: '100%' }}>
          <div>
            <Text strong>总执行时间: </Text>
            <Tag color="blue">{totalTime}ms</Tag>
          </div>
          
          <div>
            <Text strong>用户代码占比: </Text>
            <Tag color="green">
              {actualCallStack.length > 0 ? Math.round((actualCallStack.filter((f: CallStackFrame) => f.isUserCode).length / actualCallStack.length) * 100) : 0}%
            </Tag>
          </div>
          
          {slowFrames.length > 0 && (
            <div>
              <Text strong>性能瓶颈: </Text>
              <Tag color="orange" icon={<WarningOutlined />}>
                发现 {slowFrames.length} 个慢执行函数
              </Tag>
            </div>
          )}
          
          <Collapse size="small">
            <Panel header="优化建议" key="1">
              <Space orientation="vertical">
                <Text>• 考虑对API请求添加缓存机制</Text>
                <Text>• 避免在点击处理函数中执行耗时操作</Text>
                <Text>• 使用防抖或节流来优化用户交互</Text>
              </Space>
            </Panel>
          </Collapse>
        </Space>
      </Card>
    );
  };

  return (
    <Modal
      title={
        <Space>
          <BugOutlined />
          <span>调用栈分析 - Request {requestId}</span>
        </Space>
      }
      open={visible}
      onCancel={onClose}
      width={1000}
      footer={
        <Space>
          <Button onClick={onClose}>关闭</Button>
          <Button type="primary" icon={<InfoCircleOutlined />}>
            生成分析报告
          </Button>
        </Space>
      }
    >
      <div style={{ display: 'flex', gap: 16, height: 600 }}>
        {/* 左侧：调用栈树 */}
        <div style={{ flex: 1 }}>
          <Title level={5}>调用栈追踪</Title>
          <Card size="small" style={{ height: '100%', overflow: 'auto' }}>
            <Tree
              treeData={treeData}
              expandedKeys={expandedKeys}
              onExpand={(keys) => setExpandedKeys(keys as string[])}
              onSelect={(selectedKeys) => {
                if (selectedKeys.length > 0) {
                  const frameId = selectedKeys[0] as string;
                  const frame = actualCallStack.find((f: CallStackFrame) => f.id === frameId);
                  if (frame) {
                    setSelectedFrame(frame);
                  }
                }
              }}
              showLine
              showIcon
            />
          </Card>
        </div>

        {/* 右侧：详细信息 */}
        <div style={{ flex: 1 }}>
          <Title level={5}>详细信息</Title>
          <Space orientation="vertical" style={{ width: '100%' }}>
            {selectedFrame ? (
              renderFrameDetails(selectedFrame)
            ) : (
              <Card size="small">
                <Text type="secondary">点击左侧调用栈项目查看详细信息</Text>
              </Card>
            )}
            
            {getPerformanceAnalysis()}
          </Space>
        </div>
      </div>
    </Modal>
  );
};

export default CallStackAnalyzer;
