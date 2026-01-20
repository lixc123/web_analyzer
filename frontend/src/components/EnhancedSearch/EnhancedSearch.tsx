import React, { useState } from 'react';
import { Input, Select, Space, Tag, Card } from 'antd';
import { SearchOutlined } from '@ant-design/icons';

interface SearchResult {
  id: string;
  type: 'url' | 'header' | 'body' | 'cookie';
  content: string;
  matchCount: number;
}

interface EnhancedSearchProps {
  onSearch: (query: string, mode: string, scope: string[]) => void;
  results?: SearchResult[];
}

const EnhancedSearch: React.FC<EnhancedSearchProps> = ({ onSearch, results = [] }) => {
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<'text' | 'regex'>('text');
  const [scope, setScope] = useState<string[]>(['url', 'header', 'body', 'cookie']);

  const handleSearch = (value: string) => {
    setQuery(value);
    onSearch(value, mode, scope);
  };

  const highlightMatch = (text: string, query: string, isRegex: boolean) => {
    if (!query) return text;

    try {
      const regex = isRegex ? new RegExp(query, 'gi') : new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const parts = text.split(regex);
      const matches = text.match(regex) || [];

      return parts.map((part, i) => (
        <span key={i}>
          {part}
          {matches[i] && <mark style={{ backgroundColor: '#ffeb3b' }}>{matches[i]}</mark>}
        </span>
      ));
    } catch {
      return text;
    }
  };

  return (
    <Card title="全文搜索">
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Space.Compact style={{ width: '100%' }}>
          <Input
            placeholder="搜索URL、Headers、Body、Cookie"
            prefix={<SearchOutlined />}
            value={query}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: '60%' }}
          />
          <Select
            value={mode}
            onChange={setMode}
            style={{ width: '20%' }}
          >
            <Select.Option value="text">文本</Select.Option>
            <Select.Option value="regex">正则</Select.Option>
          </Select>
          <Select
            mode="multiple"
            value={scope}
            onChange={setScope}
            placeholder="搜索范围"
            style={{ width: '20%' }}
          >
            <Select.Option value="url">URL</Select.Option>
            <Select.Option value="header">Headers</Select.Option>
            <Select.Option value="body">Body</Select.Option>
            <Select.Option value="cookie">Cookie</Select.Option>
          </Select>
        </Space.Compact>

        {results.length > 0 && (
          <div>
            <div style={{ marginBottom: 8 }}>
              找到 <Tag color="blue">{results.length}</Tag> 个匹配结果
            </div>
            <Space direction="vertical" style={{ width: '100%' }}>
              {results.map(result => (
                <Card key={result.id} size="small">
                  <div>
                    <Tag color="green">{result.type.toUpperCase()}</Tag>
                    <Tag>{result.matchCount} 处匹配</Tag>
                  </div>
                  <div style={{ marginTop: 8, fontSize: 12, fontFamily: 'monospace' }}>
                    {highlightMatch(result.content, query, mode === 'regex')}
                  </div>
                </Card>
              ))}
            </Space>
          </div>
        )}
      </Space>
    </Card>
  );
};

export default EnhancedSearch;
