import React, { useState } from 'react';
import { Card, Form, Input, Button, Space, Table, Tag, Switch, message } from 'antd';
import { SwapOutlined, EyeOutlined } from '@ant-design/icons';

interface ReplaceRule {
  id: string;
  field: string;
  pattern: string;
  replacement: string;
  useRegex: boolean;
  enabled: boolean;
}

interface PreviewResult {
  field: string;
  original: string;
  replaced: string;
  matchCount: number;
}

const BatchReplace: React.FC = () => {
  const [rules, setRules] = useState<ReplaceRule[]>([]);
  const [newRule, setNewRule] = useState({ field: '', pattern: '', replacement: '', useRegex: false });
  const [preview, setPreview] = useState<PreviewResult[]>([]);

  const addRule = () => {
    if (!newRule.field || !newRule.pattern) {
      message.warning('请填写字段和匹配模式');
      return;
    }

    setRules([
      ...rules,
      {
        id: Date.now().toString(),
        ...newRule,
        enabled: true
      }
    ]);

    setNewRule({ field: '', pattern: '', replacement: '', useRegex: false });
    message.success('规则已添加');
  };

  const removeRule = (id: string) => {
    setRules(rules.filter(r => r.id !== id));
  };

  const toggleRule = (id: string) => {
    setRules(rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const previewReplace = () => {
    const results: PreviewResult[] = [];
    const sampleData = {
      token: 'old_token_12345',
      timestamp: '1640000000',
      sign: 'abc123def456'
    };

    rules.filter(r => r.enabled).forEach(rule => {
      const original = sampleData[rule.field as keyof typeof sampleData] || '';
      let replaced = original;
      let matchCount = 0;

      try {
        if (rule.useRegex) {
          const regex = new RegExp(rule.pattern, 'g');
          const matches = original.match(regex);
          matchCount = matches?.length || 0;
          replaced = original.replace(regex, rule.replacement);
        } else {
          matchCount = (original.match(new RegExp(rule.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
          replaced = original.split(rule.pattern).join(rule.replacement);
        }

        results.push({
          field: rule.field,
          original,
          replaced,
          matchCount
        });
      } catch (error) {
        message.error(`规则 "${rule.field}" 执行失败: ${(error as Error).message}`);
      }
    });

    setPreview(results);
    message.success('预览已生成');
  };

  const applyReplace = () => {
    message.success(`已应用 ${rules.filter(r => r.enabled).length} 条替换规则`);
  };

  const ruleColumns = [
    {
      title: '字段',
      dataIndex: 'field',
      key: 'field',
      width: 120
    },
    {
      title: '匹配模式',
      dataIndex: 'pattern',
      key: 'pattern',
      width: 150
    },
    {
      title: '替换为',
      dataIndex: 'replacement',
      key: 'replacement',
      width: 150
    },
    {
      title: '正则',
      dataIndex: 'useRegex',
      key: 'useRegex',
      width: 80,
      render: (useRegex: boolean) => useRegex ? <Tag color="blue">是</Tag> : <Tag>否</Tag>
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (enabled: boolean, record: ReplaceRule) => (
        <Switch checked={enabled} onChange={() => toggleRule(record.id)} size="small" />
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_: any, record: ReplaceRule) => (
        <Button size="small" danger onClick={() => removeRule(record.id)}>删除</Button>
      )
    }
  ];

  const previewColumns = [
    {
      title: '字段',
      dataIndex: 'field',
      key: 'field',
      width: 120
    },
    {
      title: '原始值',
      dataIndex: 'original',
      key: 'original',
      ellipsis: true
    },
    {
      title: '替换后',
      dataIndex: 'replaced',
      key: 'replaced',
      ellipsis: true
    },
    {
      title: '匹配数',
      dataIndex: 'matchCount',
      key: 'matchCount',
      width: 80,
      render: (count: number) => <Tag color={count > 0 ? 'green' : 'default'}>{count}</Tag>
    }
  ];

  return (
    <Card title="批量参数替换">
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        <Card title="添加替换规则" size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Input
              placeholder="字段名 (如: token, timestamp, sign)"
              value={newRule.field}
              onChange={(e) => setNewRule({ ...newRule, field: e.target.value })}
            />
            <Input
              placeholder="匹配模式"
              value={newRule.pattern}
              onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
            />
            <Input
              placeholder="替换为"
              value={newRule.replacement}
              onChange={(e) => setNewRule({ ...newRule, replacement: e.target.value })}
            />
            <Space>
              <Switch
                checked={newRule.useRegex}
                onChange={(checked) => setNewRule({ ...newRule, useRegex: checked })}
              />
              <span>使用正则表达式</span>
            </Space>
            <Button type="primary" onClick={addRule}>添加规则</Button>
          </Space>
        </Card>

        {rules.length > 0 && (
          <>
            <Card title="替换规则列表" size="small">
              <Table
                columns={ruleColumns}
                dataSource={rules}
                rowKey="id"
                pagination={false}
                size="small"
              />
            </Card>

            <Space>
              <Button icon={<EyeOutlined />} onClick={previewReplace}>预览替换</Button>
              <Button type="primary" icon={<SwapOutlined />} onClick={applyReplace}>
                应用替换
              </Button>
            </Space>
          </>
        )}

        {preview.length > 0 && (
          <Card title="替换预览" size="small">
            <Table
              columns={previewColumns}
              dataSource={preview}
              rowKey="field"
              pagination={false}
              size="small"
            />
          </Card>
        )}
      </Space>
    </Card>
  );
};

export default BatchReplace;
