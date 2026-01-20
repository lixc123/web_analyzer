import React, { useState } from 'react';
import { Card, Form, Input, Select, Button, Space, DatePicker, InputNumber, Tag } from 'antd';
import { FilterOutlined, SaveOutlined, DeleteOutlined } from '@ant-design/icons';
import type { Dayjs } from 'dayjs';

const { RangePicker } = DatePicker;

interface FilterCondition {
  urlPattern?: string;
  urlMode?: 'contains' | 'regex' | 'wildcard';
  methods?: string[];
  statusCodes?: string[];
  timeRange?: [Dayjs, Dayjs];
  minSize?: number;
  maxSize?: number;
  minDuration?: number;
  maxDuration?: number;
}

interface FilterPreset {
  name: string;
  condition: FilterCondition;
}

const AdvancedFilter: React.FC<{ onFilter: (condition: FilterCondition) => void }> = ({ onFilter }) => {
  const [form] = Form.useForm();
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [currentPreset, setCurrentPreset] = useState<string>('');

  const handleFilter = () => {
    const values = form.getFieldsValue();
    onFilter(values);
  };

  const handleReset = () => {
    form.resetFields();
    onFilter({});
  };

  const savePreset = () => {
    const values = form.getFieldsValue();
    const name = prompt('输入预设名称:');
    if (name) {
      setPresets([...presets, { name, condition: values }]);
    }
  };

  const loadPreset = (name: string) => {
    const preset = presets.find(p => p.name === name);
    if (preset) {
      form.setFieldsValue(preset.condition);
      setCurrentPreset(name);
    }
  };

  const deletePreset = (name: string) => {
    setPresets(presets.filter(p => p.name !== name));
    if (currentPreset === name) setCurrentPreset('');
  };

  return (
    <Card title="高级过滤器" extra={
      <Space>
        <Button icon={<SaveOutlined />} onClick={savePreset}>保存预设</Button>
      </Space>
    }>
      <Form form={form} layout="vertical">
        <Form.Item label="URL模式" name="urlPattern">
          <Input placeholder="输入URL模式" />
        </Form.Item>

        <Form.Item label="匹配模式" name="urlMode">
          <Select placeholder="选择匹配模式" defaultValue="contains">
            <Select.Option value="contains">包含</Select.Option>
            <Select.Option value="wildcard">通配符</Select.Option>
            <Select.Option value="regex">正则表达式</Select.Option>
          </Select>
        </Form.Item>

        <Form.Item label="请求方法" name="methods">
          <Select mode="multiple" placeholder="选择请求方法">
            <Select.Option value="GET">GET</Select.Option>
            <Select.Option value="POST">POST</Select.Option>
            <Select.Option value="PUT">PUT</Select.Option>
            <Select.Option value="DELETE">DELETE</Select.Option>
            <Select.Option value="PATCH">PATCH</Select.Option>
          </Select>
        </Form.Item>

        <Form.Item label="状态码" name="statusCodes">
          <Select mode="multiple" placeholder="选择状态码范围">
            <Select.Option value="2xx">2xx 成功</Select.Option>
            <Select.Option value="3xx">3xx 重定向</Select.Option>
            <Select.Option value="4xx">4xx 客户端错误</Select.Option>
            <Select.Option value="5xx">5xx 服务器错误</Select.Option>
          </Select>
        </Form.Item>

        <Form.Item label="时间范围" name="timeRange">
          <RangePicker showTime style={{ width: '100%' }} />
        </Form.Item>

        <Form.Item label="请求大小 (bytes)">
          <Space>
            <Form.Item name="minSize" noStyle>
              <InputNumber placeholder="最小" min={0} />
            </Form.Item>
            <span>-</span>
            <Form.Item name="maxSize" noStyle>
              <InputNumber placeholder="最大" min={0} />
            </Form.Item>
          </Space>
        </Form.Item>

        <Form.Item label="响应时间 (ms)">
          <Space>
            <Form.Item name="minDuration" noStyle>
              <InputNumber placeholder="最小" min={0} />
            </Form.Item>
            <span>-</span>
            <Form.Item name="maxDuration" noStyle>
              <InputNumber placeholder="最大" min={0} />
            </Form.Item>
          </Space>
        </Form.Item>

        <Form.Item>
          <Space>
            <Button type="primary" icon={<FilterOutlined />} onClick={handleFilter}>
              应用过滤
            </Button>
            <Button onClick={handleReset}>重置</Button>
          </Space>
        </Form.Item>
      </Form>

      {presets.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ marginBottom: 8 }}>已保存的预设:</div>
          <Space wrap>
            {presets.map(preset => (
              <Tag
                key={preset.name}
                color={currentPreset === preset.name ? 'blue' : 'default'}
                closable
                onClose={() => deletePreset(preset.name)}
                onClick={() => loadPreset(preset.name)}
                style={{ cursor: 'pointer' }}
              >
                {preset.name}
              </Tag>
            ))}
          </Space>
        </div>
      )}
    </Card>
  );
};

export default AdvancedFilter;
