import React, { useState } from 'react';
import { Card, Button, Table, Tag, Space, Descriptions, message } from 'antd';
import { SearchOutlined } from '@ant-design/icons';

interface SignatureParam {
  name: string;
  confidence: number;
  sample_value?: string;
}

interface AlgorithmHint {
  algorithm: string;
  confidence: number;
  indicators: string[];
}

interface SignaturePattern {
  params: string[];
  frequency: number;
}

interface AnalysisResult {
  total_requests: number;
  signature_params: SignatureParam[];
  timestamp_params: SignatureParam[];
  algorithm_hints: AlgorithmHint[];
  patterns: SignaturePattern[];
}

const SignatureAnalysis: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const runAnalysis = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/analysis/signature-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests: [] })
      });

      if (response.ok) {
        const data: AnalysisResult = await response.json();
        setResult(data);
        message.success('签名分析完成');
      }
    } catch (error) {
      message.error('分析失败: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const signatureColumns = [
    {
      title: '参数名',
      dataIndex: 'name',
      key: 'name'
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (confidence: number) => (
        <Tag color={confidence >= 80 ? 'green' : confidence >= 50 ? 'orange' : 'red'}>
          {confidence}%
        </Tag>
      )
    },
    {
      title: '示例值',
      dataIndex: 'sample_value',
      key: 'sample_value',
      ellipsis: true
    }
  ];

  const algorithmColumns = [
    {
      title: '算法',
      dataIndex: 'algorithm',
      key: 'algorithm',
      render: (algo: string) => <Tag color="blue">{algo}</Tag>
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (confidence: number) => `${confidence}%`
    },
    {
      title: '特征指标',
      dataIndex: 'indicators',
      key: 'indicators',
      render: (indicators: string[]) => (
        <Space>
          {indicators.map((ind, idx) => (
            <Tag key={idx}>{ind}</Tag>
          ))}
        </Space>
      )
    }
  ];

  return (
    <Card title="签名分析">
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        <Button
          type="primary"
          icon={<SearchOutlined />}
          onClick={runAnalysis}
          loading={loading}
        >
          开始分析
        </Button>

        {result && (
          <>
            <Descriptions bordered column={2}>
              <Descriptions.Item label="分析请求数">{result.total_requests}</Descriptions.Item>
              <Descriptions.Item label="识别签名参数">{result.signature_params.length}</Descriptions.Item>
              <Descriptions.Item label="时间戳参数">{result.timestamp_params.length}</Descriptions.Item>
              <Descriptions.Item label="算法提示">{result.algorithm_hints.length}</Descriptions.Item>
            </Descriptions>

            <Card title="识别的签名参数" size="small">
              <Table
                columns={signatureColumns}
                dataSource={result.signature_params}
                rowKey="name"
                pagination={false}
                size="small"
              />
            </Card>

            <Card title="时间戳参数" size="small">
              <Table
                columns={signatureColumns}
                dataSource={result.timestamp_params}
                rowKey="name"
                pagination={false}
                size="small"
              />
            </Card>

            <Card title="算法提示" size="small">
              <Table
                columns={algorithmColumns}
                dataSource={result.algorithm_hints}
                rowKey="algorithm"
                pagination={false}
                size="small"
              />
            </Card>
          </>
        )}
      </Space>
    </Card>
  );
};

export default SignatureAnalysis;
