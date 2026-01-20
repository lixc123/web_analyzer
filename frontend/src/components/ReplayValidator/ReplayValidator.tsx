import React, { useState } from 'react';
import { Card, Button, Table, Tag, Space, Statistic, Row, Col, Modal, message } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, SyncOutlined } from '@ant-design/icons';

interface ValidationResult {
  request_id: string;
  method: string;
  url: string;
  status: 'success' | 'failed';
  reason?: string;
  original_status?: number;
  replay_status?: number;
  response_diff?: string;
}

interface ValidationReport {
  total: number;
  success: number;
  failed: number;
  results: ValidationResult[];
}

const ReplayValidator: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ValidationReport | null>(null);
  const [selectedResult, setSelectedResult] = useState<ValidationResult | null>(null);
  const [showDiffModal, setShowDiffModal] = useState(false);

  const runValidation = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/analysis/replay-validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests: [] })
      });

      if (response.ok) {
        const data: ValidationReport = await response.json();
        setReport(data);
        message.success('验证完成');
      }
    } catch (error) {
      message.error('验证失败: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status: string) => (
        status === 'success' ? (
          <Tag icon={<CheckCircleOutlined />} color="success">成功</Tag>
        ) : (
          <Tag icon={<CloseCircleOutlined />} color="error">失败</Tag>
        )
      )
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true
    },
    {
      title: '原始状态码',
      dataIndex: 'original_status',
      key: 'original_status',
      width: 100
    },
    {
      title: '重放状态码',
      dataIndex: 'replay_status',
      key: 'replay_status',
      width: 100
    },
    {
      title: '失败原因',
      dataIndex: 'reason',
      key: 'reason',
      width: 150,
      render: (reason?: string) => reason ? <Tag color="red">{reason}</Tag> : '-'
    },
    {
      title: '操作',
      key: 'action',
      width: 100,
      render: (_: any, record: ValidationResult) => (
        <Button
          size="small"
          onClick={() => {
            setSelectedResult(record);
            setShowDiffModal(true);
          }}
          disabled={!record.response_diff}
        >
          查看差异
        </Button>
      )
    }
  ];

  return (
    <>
      <Card title="重放验证">
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Button
            type="primary"
            icon={<SyncOutlined />}
            onClick={runValidation}
            loading={loading}
          >
            开始验证
          </Button>

          {report && (
            <>
              <Row gutter={16}>
                <Col span={8}>
                  <Card>
                    <Statistic title="总计" value={report.total} />
                  </Card>
                </Col>
                <Col span={8}>
                  <Card>
                    <Statistic
                      title="成功"
                      value={report.success}
                      valueStyle={{ color: '#3f8600' }}
                      prefix={<CheckCircleOutlined />}
                    />
                  </Card>
                </Col>
                <Col span={8}>
                  <Card>
                    <Statistic
                      title="失败"
                      value={report.failed}
                      valueStyle={{ color: '#cf1322' }}
                      prefix={<CloseCircleOutlined />}
                    />
                  </Card>
                </Col>
              </Row>

              <Table
                columns={columns}
                dataSource={report.results}
                rowKey="request_id"
                pagination={{ pageSize: 10 }}
              />
            </>
          )}
        </Space>
      </Card>

      <Modal
        title="响应差异对比"
        open={showDiffModal}
        onCancel={() => setShowDiffModal(false)}
        width={800}
        footer={null}
      >
        {selectedResult && (
          <div>
            <h4>请求信息</h4>
            <p><strong>方法:</strong> {selectedResult.method}</p>
            <p><strong>URL:</strong> {selectedResult.url}</p>
            <h4>响应差异</h4>
            <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, maxHeight: 400, overflow: 'auto' }}>
              {selectedResult.response_diff || '无差异数据'}
            </pre>
          </div>
        )}
      </Modal>
    </>
  );
};

export default ReplayValidator;
