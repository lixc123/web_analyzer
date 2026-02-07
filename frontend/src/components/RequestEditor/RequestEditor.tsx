import React, { useState } from 'react';
import { Card, Input, Select, Button, Space, Tabs, message, Spin } from 'antd';
import { SendOutlined, CopyOutlined } from '@ant-design/icons';

const { TextArea } = Input;

interface RequestData {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

interface ResponseData {
  status: number;
  headers: Record<string, string>;
  body: string;
  duration: number;
}

const RequestEditor: React.FC<{ initialRequest?: RequestData }> = ({ initialRequest }) => {
  const [method, setMethod] = useState(initialRequest?.method || 'GET');
  const [url, setUrl] = useState(initialRequest?.url || '');
  const [headers, setHeaders] = useState(JSON.stringify(initialRequest?.headers || {}, null, 2));
  const [body, setBody] = useState(initialRequest?.body || '');
  const [response, setResponse] = useState<ResponseData | null>(null);
  const [loading, setLoading] = useState(false);

  const sendRequest = async () => {
    try {
      setLoading(true);
      const startTime = Date.now();

      const res = await fetch('/api/v1/request-analysis/replay-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method,
          url,
          headers: JSON.parse(headers),
          payload: body ? JSON.parse(body) : undefined
        })
      });

      const data = await res.json();
      const duration = Date.now() - startTime;

      setResponse({
        status: data.status || res.status,
        headers: data.headers || {},
        body: JSON.stringify(data.body || data, null, 2),
        duration
      });

      message.success('请求发送成功');
    } catch (error) {
      message.error('请求失败: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const copyAsCurl = () => {
    let curl = `curl -X ${method} "${url}"`;
    try {
      const headerObj = JSON.parse(headers);
      Object.entries(headerObj).forEach(([key, value]) => {
        curl += ` \\\n  -H "${key}: ${value}"`;
      });
      if (body && method !== 'GET') {
        curl += ` \\\n  -d '${body}'`;
      }
      navigator.clipboard.writeText(curl);
      message.success('已复制为cURL命令');
    } catch {
      message.error('格式错误');
    }
  };

  return (
    <Card title="请求编辑器 (Repeater)">
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Space.Compact style={{ width: '100%' }}>
          <Select value={method} onChange={setMethod} style={{ width: 120 }}>
            <Select.Option value="GET">GET</Select.Option>
            <Select.Option value="POST">POST</Select.Option>
            <Select.Option value="PUT">PUT</Select.Option>
            <Select.Option value="DELETE">DELETE</Select.Option>
            <Select.Option value="PATCH">PATCH</Select.Option>
          </Select>
          <Input
            placeholder="请求URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{ flex: 1 }}
          />
          <Button type="primary" icon={<SendOutlined />} onClick={sendRequest} loading={loading}>
            发送
          </Button>
          <Button icon={<CopyOutlined />} onClick={copyAsCurl}>
            复制cURL
          </Button>
        </Space.Compact>

        <Tabs
          items={[
            {
              key: 'headers',
              label: 'Headers',
              children: (
                <TextArea
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  placeholder='{"Content-Type": "application/json"}'
                  rows={8}
                  style={{ fontFamily: 'monospace' }}
                />
              )
            },
            {
              key: 'body',
              label: 'Body',
              children: (
                <TextArea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder='{"key": "value"}'
                  rows={8}
                  style={{ fontFamily: 'monospace' }}
                />
              )
            }
          ]}
        />

        {loading && <Spin tip="发送中..." />}

        {response && (
          <Card title={`响应 (${response.status}) - ${response.duration}ms`} size="small">
            <Tabs
              items={[
                {
                  key: 'response-headers',
                  label: 'Headers',
                  children: (
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, maxHeight: 200, overflow: 'auto' }}>
                      {JSON.stringify(response.headers, null, 2)}
                    </pre>
                  )
                },
                {
                  key: 'response-body',
                  label: 'Body',
                  children: (
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, maxHeight: 400, overflow: 'auto' }}>
                      {response.body}
                    </pre>
                  )
                }
              ]}
            />
          </Card>
        )}
      </Space>
    </Card>
  );
};

export default RequestEditor;
