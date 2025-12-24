import React, { useState, useEffect } from 'react';
import {
  Card,
  Button,
  Space,
  Typography,
  Progress,
  Alert,
  Modal,
  Statistic,
  Row,
  Col,
  Timeline,
  Tag,
  message,
  Switch
} from 'antd';
import {
  CompressOutlined,
  ClearOutlined,
  BarChartOutlined,
  FileTextOutlined,
  ExclamationCircleOutlined,
  ThunderboltOutlined,
  SaveOutlined
} from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;

// Token使用情况接口
interface TokenUsage {
  total: number;
  limit: number;
  percentage: number;
  breakdown: {
    input: number;
    output: number;
    system: number;
  };
  history: TokenHistoryItem[];
}

interface TokenHistoryItem {
  timestamp: Date;
  tokens: number;
  type: 'user' | 'assistant' | 'system';
  messageId: string;
  compressed: boolean;
}

// 会话压缩结果
interface CompressionResult {
  originalTokens: number;
  compressedTokens: number;
  compressionRatio: number;
  summary: string;
  preservedMessages: number;
  removedMessages: number;
  estimatedSavings: number;
}

// 压缩策略
interface CompressionStrategy {
  id: string;
  name: string;
  description: string;
  aggressiveness: number; // 1-5，压缩激进程度
  preserveRecent: number; // 保留最近N条消息
  summarizeOlder: boolean; // 是否总结较早的消息
  removeSystem: boolean; // 是否移除系统消息
}

const COMPRESSION_STRATEGIES: CompressionStrategy[] = [
  {
    id: 'conservative',
    name: '保守压缩',
    description: '保留更多上下文，适合复杂对话',
    aggressiveness: 2,
    preserveRecent: 20,
    summarizeOlder: true,
    removeSystem: false
  },
  {
    id: 'balanced',
    name: '平衡压缩',
    description: '平衡压缩率和上下文保留',
    aggressiveness: 3,
    preserveRecent: 15,
    summarizeOlder: true,
    removeSystem: true
  },
  {
    id: 'aggressive',
    name: '激进压缩',
    description: '最大化压缩，节省更多Token',
    aggressiveness: 4,
    preserveRecent: 10,
    summarizeOlder: true,
    removeSystem: true
  }
];

interface SessionCompressionProps {
  sessionId: string;
  tokenUsage: TokenUsage;
  onCompressionComplete: (result: CompressionResult) => void;
  autoCompressionEnabled?: boolean;
}

export const SessionCompression: React.FC<SessionCompressionProps> = ({
  sessionId,
  tokenUsage,
  onCompressionComplete,
  autoCompressionEnabled = true
}) => {
  const [compressionHistory, setCompressionHistory] = useState<CompressionResult[]>([]);
  const [isCompressing, setIsCompressing] = useState(false);
  const [showCompressionModal, setShowCompressionModal] = useState(false);
  const [selectedStrategy, setSelectedStrategy] = useState<CompressionStrategy>(COMPRESSION_STRATEGIES[1]);
  const [autoCompress, setAutoCompress] = useState(autoCompressionEnabled);
  const [lastCompressionTime, setLastCompressionTime] = useState<Date | null>(null);

  // 检查是否需要压缩
  const shouldCompress = () => {
    if (!autoCompress) return false;
    if (tokenUsage.percentage >= 80) return true;
    if (tokenUsage.total > 3000 && !lastCompressionTime) return true;
    if (lastCompressionTime && 
        (new Date().getTime() - lastCompressionTime.getTime()) > 30 * 60 * 1000 && // 30分钟
        tokenUsage.total > 2000) return true;
    return false;
  };

  // 自动压缩检查
  useEffect(() => {
    if (shouldCompress()) {
      message.info({
        content: (
          <div>
            <span>Token使用量过高，建议执行压缩</span>
            <Button 
              size="small" 
              type="link" 
              onClick={() => setShowCompressionModal(true)}
            >
              立即压缩
            </Button>
          </div>
        ),
        duration: 10,
        key: 'compression-suggestion'
      });
    }
  }, [tokenUsage.percentage, autoCompress]);

  // 执行压缩
  const performCompression = async (strategy: CompressionStrategy) => {
    setIsCompressing(true);
    try {
      const response = await fetch('/api/v1/commands/session/compress', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          strategy: strategy.id,
          preserve_recent: strategy.preserveRecent,
          summarize_older: strategy.summarizeOlder,
          remove_system: strategy.removeSystem
        })
      });

      if (!response.ok) throw new Error('压缩失败');

      const result: CompressionResult = await response.json();
      
      // 更新压缩历史
      setCompressionHistory(prev => [...prev, result]);
      setLastCompressionTime(new Date());
      
      // 通知父组件
      onCompressionComplete(result);
      
      setShowCompressionModal(false);
      message.success(`压缩完成！节省了 ${result.estimatedSavings} tokens (${(result.compressionRatio * 100).toFixed(1)}%)`);

    } catch (error) {
      message.error(`压缩失败: ${error}`);
    } finally {
      setIsCompressing(false);
    }
  };

  // 清除会话历史
  const clearSession = () => {
    Modal.confirm({
      title: '确认清除会话',
      icon: <ExclamationCircleOutlined />,
      content: '这将删除所有对话历史，无法恢复。建议先进行压缩以保留总结。',
      okText: '确认清除',
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        try {
          const response = await fetch(`/api/v1/commands/session/clear/${sessionId}`, {
            method: 'POST'
          });

          if (!response.ok) throw new Error('清除失败');

          const result = await response.json();
          message.success(result.message);
          
          // 重置Token统计
          onCompressionComplete({
            originalTokens: tokenUsage.total,
            compressedTokens: 0,
            compressionRatio: 1,
            summary: '会话已完全清除',
            preservedMessages: 0,
            removedMessages: result.cleared_items,
            estimatedSavings: tokenUsage.total
          });

        } catch (error) {
          message.error(`清除失败: ${error}`);
        }
      }
    });
  };

  // 获取Token使用状态颜色
  const getTokenStatusColor = (percentage: number) => {
    if (percentage >= 90) return '#ff4d4f';
    if (percentage >= 80) return '#faad14';
    if (percentage >= 60) return '#1890ff';
    return '#52c41a';
  };

  // 渲染压缩建议
  const renderCompressionSuggestion = () => {
    if (tokenUsage.percentage < 60) return null;

    const urgency = tokenUsage.percentage >= 90 ? 'error' : 
                   tokenUsage.percentage >= 80 ? 'warning' : 'info';

    return (
      <Alert
        type={urgency}
        showIcon
        title="Token使用提醒"
        description={
          <div>
            <p>当前Token使用率: {tokenUsage.percentage.toFixed(1)}%</p>
            {tokenUsage.percentage >= 90 && (
              <p>⚠️ Token即将用完，请立即执行压缩或清除操作</p>
            )}
            {tokenUsage.percentage >= 80 && tokenUsage.percentage < 90 && (
              <p>💡 建议执行压缩以释放空间，继续对话</p>
            )}
            {tokenUsage.percentage >= 60 && tokenUsage.percentage < 80 && (
              <p>ℹ️ Token使用较多，可考虑适当压缩</p>
            )}
          </div>
        }
        action={
          <Space>
            <Button 
              size="small" 
              type="primary"
              onClick={() => setShowCompressionModal(true)}
            >
              压缩
            </Button>
            <Button 
              size="small" 
              danger
              onClick={clearSession}
            >
              清除
            </Button>
          </Space>
        }
        style={{ marginBottom: 16 }}
      />
    );
  };

  return (
    <div>
      {/* Token使用状态卡片 */}
      <Card 
        title={
          <Space>
            <BarChartOutlined />
            <span>Token使用监控</span>
            <Switch 
              checked={autoCompress}
              onChange={setAutoCompress}
              size="small"
            />
            <Text type="secondary" style={{ fontSize: '12px' }}>自动提醒</Text>
          </Space>
        }
        size="small"
        style={{ marginBottom: 16 }}
      >
        <Row gutter={16}>
          <Col span={8}>
            <Statistic
              title="总使用量"
              value={tokenUsage.total}
              suffix={`/ ${tokenUsage.limit || '∞'}`}
              valueStyle={{ color: getTokenStatusColor(tokenUsage.percentage) }}
            />
          </Col>
          <Col span={8}>
            <Statistic
              title="使用率"
              value={tokenUsage.percentage}
              precision={1}
              suffix="%"
              valueStyle={{ color: getTokenStatusColor(tokenUsage.percentage) }}
            />
          </Col>
          <Col span={8}>
            <div>
              <Text type="secondary">使用分布</Text>
              <div style={{ marginTop: 4 }}>
                <Tag color="blue">输入: {tokenUsage.breakdown.input}</Tag>
                <Tag color="green">输出: {tokenUsage.breakdown.output}</Tag>
                <Tag color="orange">系统: {tokenUsage.breakdown.system}</Tag>
              </div>
            </div>
          </Col>
        </Row>

        <div style={{ marginTop: 16 }}>
          <Progress
            percent={tokenUsage.percentage}
            strokeColor={getTokenStatusColor(tokenUsage.percentage)}
            showInfo={false}
            size="small"
          />
        </div>

        <div style={{ marginTop: 12, textAlign: 'right' }}>
          <Space>
            <Button 
              icon={<CompressOutlined />}
              onClick={() => setShowCompressionModal(true)}
              disabled={tokenUsage.total < 500}
            >
              压缩会话
            </Button>
            <Button 
              icon={<ClearOutlined />}
              onClick={clearSession}
              danger
            >
              清除会话
            </Button>
          </Space>
        </div>
      </Card>

      {/* 压缩建议提醒 */}
      {renderCompressionSuggestion()}

      {/* 压缩历史 */}
      {compressionHistory.length > 0 && (
        <Card 
          title="压缩历史"
          size="small"
          style={{ marginBottom: 16 }}
        >
          <Timeline>
            {compressionHistory.slice(-5).map((compression, index) => (
              <Timeline.Item
                key={index}
                dot={<CompressOutlined style={{ fontSize: '12px' }} />}
                color="blue"
              >
                <div>
                  <Text strong>
                    节省 {compression.estimatedSavings} tokens 
                    ({(compression.compressionRatio * 100).toFixed(1)}% 压缩率)
                  </Text>
                  <div style={{ fontSize: '12px', color: '#666', marginTop: 4 }}>
                    保留 {compression.preservedMessages} 条消息，
                    移除 {compression.removedMessages} 条消息
                  </div>
                  {compression.summary && (
                    <Paragraph 
                      ellipsis={{ rows: 2, expandable: true }}
                      style={{ fontSize: '12px', marginTop: 4, marginBottom: 0 }}
                    >
                      摘要: {compression.summary}
                    </Paragraph>
                  )}
                </div>
              </Timeline.Item>
            ))}
          </Timeline>
        </Card>
      )}

      {/* 压缩策略选择模态框 */}
      <Modal
        title="会话压缩"
        open={showCompressionModal}
        onCancel={() => setShowCompressionModal(false)}
        footer={null}
        width={700}
      >
        <div style={{ marginBottom: 16 }}>
          <Alert
            title="压缩说明"
            description="压缩会将较早的对话内容总结为简短摘要，保留最近的重要对话，从而节省Token使用量。压缩后无法恢复原始对话。"
            type="info"
            showIcon
          />
        </div>

        <Title level={5}>选择压缩策略</Title>
        
        <Row gutter={16} style={{ marginBottom: 24 }}>
          {COMPRESSION_STRATEGIES.map(strategy => (
            <Col span={8} key={strategy.id}>
              <Card
                size="small"
                hoverable
                style={{ 
                  border: selectedStrategy.id === strategy.id ? '2px solid #1890ff' : '1px solid #d9d9d9'
                }}
                onClick={() => setSelectedStrategy(strategy)}
              >
                <div style={{ textAlign: 'center' }}>
                  <Title level={5} style={{ marginBottom: 8 }}>
                    {strategy.name}
                  </Title>
                  <Paragraph style={{ fontSize: '12px', marginBottom: 12 }}>
                    {strategy.description}
                  </Paragraph>
                  <Space orientation="vertical" size="small">
                    <Text type="secondary" style={{ fontSize: '11px' }}>
                      激进度: {Array.from({length: strategy.aggressiveness}, () => '●').join('')}
                      {Array.from({length: 5 - strategy.aggressiveness}, () => '○').join('')}
                    </Text>
                    <Text type="secondary" style={{ fontSize: '11px' }}>
                      保留最近 {strategy.preserveRecent} 条
                    </Text>
                  </Space>
                </div>
              </Card>
            </Col>
          ))}
        </Row>

        <div style={{ marginBottom: 16 }}>
          <Title level={5}>压缩预览</Title>
          <Card size="small" style={{ backgroundColor: '#fafafa' }}>
            <Row gutter={16}>
              <Col span={12}>
                <Statistic
                  title="当前Token"
                  value={tokenUsage.total}
                  prefix={<FileTextOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="预估节省"
                  value={Math.floor(tokenUsage.total * (selectedStrategy.aggressiveness / 10))}
                  prefix={<ThunderboltOutlined />}
                  valueStyle={{ color: '#52c41a' }}
                />
              </Col>
            </Row>
          </Card>
        </div>

        <div style={{ textAlign: 'right' }}>
          <Space>
            <Button onClick={() => setShowCompressionModal(false)}>
              取消
            </Button>
            <Button 
              type="primary"
              icon={<SaveOutlined />}
              loading={isCompressing}
              onClick={() => performCompression(selectedStrategy)}
            >
              执行压缩
            </Button>
          </Space>
        </div>
      </Modal>
    </div>
  );
};

export default SessionCompression;
