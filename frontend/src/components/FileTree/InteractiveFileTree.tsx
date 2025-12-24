import React, { useState, useEffect, useMemo } from 'react';
import {
  Tree,
  Card,
  Button,
  Space,
  Input,
  Typography,
  Tag,
  Checkbox,
  Row,
  Col,
  Progress,
  Tooltip,
  Modal,
  message,
  Divider,
  Select,
  Badge,
  Statistic
} from 'antd';
import {
  FolderOutlined,
  FolderOpenOutlined,
  FileOutlined,
  SettingOutlined,
  ScanOutlined,
  CodeOutlined,
  FileImageOutlined,
  FileTextOutlined,
  DatabaseOutlined,
  BulbOutlined,
  EyeOutlined,
} from '@ant-design/icons';

const { Title, Text } = Typography;
const { DirectoryTree } = Tree;
const { Search } = Input;

// 文件节点接口
interface FileNode {
  key: string;
  title: string;
  path: string;
  isLeaf: boolean;
  type: 'file' | 'folder';
  size?: number;
  extension?: string;
  lastModified?: Date;
  children?: FileNode[];
  selected: boolean;
  analyzed: boolean;
  analysisResult?: FileAnalysis;
  icon?: React.ReactNode;
}

// 文件分析结果
interface FileAnalysis {
  type: 'code' | 'config' | 'data' | 'image' | 'document' | 'other';
  language?: string;
  lines?: number;
  complexity?: number;
  issues?: string[];
  suggestions?: string[];
  risk: 'low' | 'medium' | 'high';
}

// 扫描配置
interface ScanConfig {
  includeHidden: boolean;
  maxDepth: number;
  excludePatterns: string[];
  includePatterns: string[];
  autoAnalyze: boolean;
  followSymlinks: boolean;
}

const DEFAULT_SCAN_CONFIG: ScanConfig = {
  includeHidden: false,
  maxDepth: 5,
  excludePatterns: [
    'node_modules/**',
    '.git/**',
    '*.log',
    'dist/**',
    'build/**',
    '__pycache__/**',
    '*.pyc'
  ],
  includePatterns: [
    '**/*.js',
    '**/*.ts',
    '**/*.jsx', 
    '**/*.tsx',
    '**/*.py',
    '**/*.java',
    '**/*.cpp',
    '**/*.c',
    '**/*.html',
    '**/*.css',
    '**/*.json',
    '**/*.xml'
  ],
  autoAnalyze: true,
  followSymlinks: false
};

// 文件类型图标映射
const FILE_TYPE_ICONS: { [key: string]: React.ReactNode } = {
  // 代码文件
  js: <CodeOutlined style={{ color: '#f7df1e' }} />,
  ts: <CodeOutlined style={{ color: '#3178c6' }} />,
  jsx: <CodeOutlined style={{ color: '#61dafb' }} />,
  tsx: <CodeOutlined style={{ color: '#61dafb' }} />,
  py: <CodeOutlined style={{ color: '#3776ab' }} />,
  java: <CodeOutlined style={{ color: '#ed8b00' }} />,
  cpp: <CodeOutlined style={{ color: '#00599c' }} />,
  c: <CodeOutlined style={{ color: '#a8b9cc' }} />,
  
  // 样式文件
  css: <FileTextOutlined style={{ color: '#1572b6' }} />,
  scss: <FileTextOutlined style={{ color: '#cf649a' }} />,
  less: <FileTextOutlined style={{ color: '#1d365d' }} />,
  
  // 配置文件
  json: <DatabaseOutlined style={{ color: '#000000' }} />,
  xml: <FileTextOutlined style={{ color: '#e34c26' }} />,
  yaml: <FileTextOutlined style={{ color: '#cb171e' }} />,
  yml: <FileTextOutlined style={{ color: '#cb171e' }} />,
  
  // 图片文件
  png: <FileImageOutlined style={{ color: '#ff6b6b' }} />,
  jpg: <FileImageOutlined style={{ color: '#4ecdc4' }} />,
  jpeg: <FileImageOutlined style={{ color: '#4ecdc4' }} />,
  gif: <FileImageOutlined style={{ color: '#ffe66d' }} />,
  svg: <FileImageOutlined style={{ color: '#a8e6cf' }} />,
  
  // 默认
  default: <FileOutlined />
};

interface InteractiveFileTreeProps {
  projectPath?: string;
  onFilesSelected: (files: FileNode[]) => void;
  onAnalysisComplete: (results: FileAnalysis[]) => void;
}

export const InteractiveFileTree: React.FC<InteractiveFileTreeProps> = ({
  projectPath = '',
  onFilesSelected,
  onAnalysisComplete
}) => {
  const [treeData, setTreeData] = useState<FileNode[]>([]);
  const [expandedKeys, setExpandedKeys] = useState<string[]>([]);
  const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
  const [checkedKeys, setCheckedKeys] = useState<string[]>([]);
  const [searchValue, setSearchValue] = useState('');
  const [scanConfig] = useState<ScanConfig>(DEFAULT_SCAN_CONFIG);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [filterType, setFilterType] = useState<string>('all');
  const [stats, setStats] = useState({
    totalFiles: 0,
    selectedFiles: 0,
    analyzedFiles: 0,
    totalSize: 0
  });

  // 初始化扫描
  useEffect(() => {
    if (projectPath) {
      scanDirectory(projectPath);
    }
  }, [projectPath]);

  // 扫描目录
  const scanDirectory = async (path: string) => {
    setIsScanning(true);
    setScanProgress(0);
    
    try {
      const response = await fetch('/api/v1/commands/directory/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path,
          config: scanConfig
        })
      });

      if (!response.ok) throw new Error('扫描失败');

      // 使用流式响应处理进度
      const reader = response.body?.getReader();
      if (!reader) throw new Error('无法读取响应');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = new TextDecoder().decode(value);
        const lines = chunk.split('\n').filter(line => line.trim());
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = JSON.parse(line.slice(6));
            
            if (data.type === 'progress') {
              setScanProgress(data.progress);
            } else if (data.type === 'file_tree') {
              setTreeData(data.tree);
              updateStats(data.tree);
            }
          }
        }
      }

      // 自动展开根目录
      const rootKeys = treeData.filter(node => node.type === 'folder').map(node => node.key);
      setExpandedKeys(rootKeys.slice(0, 3)); // 只展开前3个文件夹

    } catch (error) {
      message.error(`目录扫描失败: ${error}`);
    } finally {
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  // 更新统计信息
  const updateStats = (nodes: FileNode[]) => {
    let totalFiles = 0;
    let selectedFiles = 0;
    let analyzedFiles = 0;
    let totalSize = 0;

    const traverse = (node: FileNode) => {
      if (node.type === 'file') {
        totalFiles++;
        totalSize += node.size || 0;
        if (node.selected) selectedFiles++;
        if (node.analyzed) analyzedFiles++;
      }
      node.children?.forEach(traverse);
    };

    nodes.forEach(traverse);
    
    setStats({ totalFiles, selectedFiles, analyzedFiles, totalSize });
  };

  // 批量分析选中文件
  const analyzeSelectedFiles = async () => {
    const selectedFiles = getSelectedFiles();
    if (selectedFiles.length === 0) {
      message.warning('请先选择要分析的文件');
      return;
    }

    try {
      const response = await fetch('/api/v1/commands/directory/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          files: selectedFiles.map(file => file.path),
          config: {
            includeComplexity: true,
            detectIssues: true,
            generateSuggestions: true
          }
        })
      });

      if (!response.ok) throw new Error('分析失败');

      const results = await response.json();
      
      // 更新文件节点的分析结果
      const updatedTree = updateAnalysisResults(treeData, results.analyses);
      setTreeData(updatedTree);
      updateStats(updatedTree);
      
      onAnalysisComplete(results.analyses);
      message.success(`成功分析了 ${results.analyses.length} 个文件`);

    } catch (error) {
      message.error(`文件分析失败: ${error}`);
    }
  };

  // 更新分析结果到树节点
  const updateAnalysisResults = (nodes: FileNode[], analyses: any[]): FileNode[] => {
    return nodes.map(node => {
      const analysis = analyses.find(a => a.path === node.path);
      const updatedNode = {
        ...node,
        analyzed: !!analysis,
        analysisResult: analysis || node.analysisResult
      };

      if (node.children) {
        updatedNode.children = updateAnalysisResults(node.children, analyses);
      }

      return updatedNode;
    });
  };

  // 获取选中的文件
  const getSelectedFiles = (): FileNode[] => {
    const files: FileNode[] = [];
    
    const traverse = (node: FileNode) => {
      if (node.type === 'file' && node.selected) {
        files.push(node);
      }
      node.children?.forEach(traverse);
    };

    treeData.forEach(traverse);
    return files;
  };

  // 文件图标渲染
  const renderFileIcon = (node: FileNode) => {
    if (node.type === 'folder') {
      return expandedKeys.includes(node.key) ? 
        <FolderOpenOutlined /> : <FolderOutlined />;
    }

    const extension = node.extension?.toLowerCase();
    return extension && FILE_TYPE_ICONS[extension] 
      ? FILE_TYPE_ICONS[extension] 
      : FILE_TYPE_ICONS.default;
  };

  // 渲染文件节点标题
  const renderNodeTitle = (node: FileNode) => {
    const isSelected = selectedKeys.includes(node.key);
    const isChecked = checkedKeys.includes(node.key);
    
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Space size="small">
          <Checkbox 
            checked={isChecked}
            onChange={(e) => {
              const newCheckedKeys = e.target.checked 
                ? [...checkedKeys, node.key]
                : checkedKeys.filter(key => key !== node.key);
              setCheckedKeys(newCheckedKeys);
              
              // 更新节点选中状态
              const updatedTree = updateNodeSelection(treeData, node.key, e.target.checked);
              setTreeData(updatedTree);
              updateStats(updatedTree);
            }}
          />
          
          {renderFileIcon(node)}
          
          <span 
            style={{ 
              fontWeight: isSelected ? 'bold' : 'normal',
              color: isSelected ? '#1890ff' : undefined 
            }}
          >
            {highlightSearchText(node.title)}
          </span>
          
          {node.type === 'file' && (
            <Text type="secondary" style={{ fontSize: '11px' }}>
              ({formatFileSize(node.size || 0)})
            </Text>
          )}
        </Space>
        
        <Space size="small">
          {node.analyzed && (
            <Tooltip title="已分析">
              <Badge status="success" />
            </Tooltip>
          )}
          
          {node.analysisResult && (
            <Tag 
              color={
                node.analysisResult.risk === 'high' ? 'red' :
                node.analysisResult.risk === 'medium' ? 'orange' : 'green'
              }
            >
              {node.analysisResult.type}
            </Tag>
          )}
          
          {node.type === 'file' && (
            <Tooltip title="查看详情">
              <Button 
                type="text" 
                size="small" 
                icon={<EyeOutlined />}
                onClick={(e) => {
                  e.stopPropagation();
                  showFileDetails(node);
                }}
              />
            </Tooltip>
          )}
        </Space>
      </div>
    );
  };

  // 更新节点选中状态
  const updateNodeSelection = (nodes: FileNode[], targetKey: string, selected: boolean): FileNode[] => {
    return nodes.map(node => {
      if (node.key === targetKey) {
        return { ...node, selected };
      }
      
      if (node.children) {
        return {
          ...node,
          children: updateNodeSelection(node.children, targetKey, selected)
        };
      }
      
      return node;
    });
  };

  // 高亮搜索文本
  const highlightSearchText = (text: string) => {
    if (!searchValue) return text;
    
    const index = text.toLowerCase().indexOf(searchValue.toLowerCase());
    if (index === -1) return text;
    
    const before = text.substring(0, index);
    const match = text.substring(index, index + searchValue.length);
    const after = text.substring(index + searchValue.length);
    
    return (
      <>
        {before}
        <span style={{ backgroundColor: '#ffe58f' }}>{match}</span>
        {after}
      </>
    );
  };

  // 格式化文件大小
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // 显示文件详情
  const showFileDetails = (node: FileNode) => {
    Modal.info({
      title: `文件详情: ${node.title}`,
      width: 600,
      content: (
        <div>
          <p><strong>路径:</strong> {node.path}</p>
          <p><strong>大小:</strong> {formatFileSize(node.size || 0)}</p>
          <p><strong>修改时间:</strong> {node.lastModified?.toLocaleString()}</p>
          
          {node.analysisResult && (
            <>
              <Divider />
              <h4>分析结果</h4>
              <p><strong>类型:</strong> {node.analysisResult.type}</p>
              <p><strong>风险等级:</strong> 
                <Tag color={
                  node.analysisResult.risk === 'high' ? 'red' :
                  node.analysisResult.risk === 'medium' ? 'orange' : 'green'
                }>
                  {node.analysisResult.risk}
                </Tag>
              </p>
              
              {node.analysisResult.language && (
                <p><strong>语言:</strong> {node.analysisResult.language}</p>
              )}
              
              {node.analysisResult.lines && (
                <p><strong>行数:</strong> {node.analysisResult.lines}</p>
              )}
              
              {node.analysisResult.issues && node.analysisResult.issues.length > 0 && (
                <>
                  <h5>发现的问题:</h5>
                  <ul>
                    {node.analysisResult.issues.map((issue, index) => (
                      <li key={index}>{issue}</li>
                    ))}
                  </ul>
                </>
              )}
              
              {node.analysisResult.suggestions && node.analysisResult.suggestions.length > 0 && (
                <>
                  <h5>改进建议:</h5>
                  <ul>
                    {node.analysisResult.suggestions.map((suggestion, index) => (
                      <li key={index}>{suggestion}</li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </div>
      )
    });
  };

  // 过滤树数据
  const filteredTreeData = useMemo(() => {
    if (!searchValue && filterType === 'all') return treeData;
    
    const filterNodes = (nodes: FileNode[]): FileNode[] => {
      return nodes.reduce((filtered: FileNode[], node) => {
        const matchesSearch = !searchValue || 
          node.title.toLowerCase().includes(searchValue.toLowerCase()) ||
          node.path.toLowerCase().includes(searchValue.toLowerCase());
        
        const matchesType = filterType === 'all' || 
          (filterType === 'analyzed' && node.analyzed) ||
          (filterType === 'selected' && node.selected) ||
          (filterType === 'code' && node.analysisResult?.type === 'code') ||
          (filterType === 'config' && node.analysisResult?.type === 'config');

        if (node.type === 'folder') {
          const filteredChildren = node.children ? filterNodes(node.children) : [];
          if (filteredChildren.length > 0 || matchesSearch) {
            filtered.push({
              ...node,
              children: filteredChildren
            });
          }
        } else if (matchesSearch && matchesType) {
          filtered.push(node);
        }
        
        return filtered;
      }, []);
    };
    
    return filterNodes(treeData);
  }, [treeData, searchValue, filterType]);

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Title level={4} style={{ margin: 0 }}>
            <ScanOutlined /> 项目文件树
          </Title>
          <Space>
            <Button 
              icon={<SettingOutlined />}
              onClick={() => setShowConfigModal(true)}
            >
              扫描配置
            </Button>
            <Button 
              type="primary"
              icon={<BulbOutlined />}
              onClick={analyzeSelectedFiles}
              disabled={checkedKeys.length === 0}
            >
              分析选中文件
            </Button>
          </Space>
        </div>

        {/* 搜索和过滤 */}
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={12}>
            <Search
              placeholder="搜索文件或文件夹"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              allowClear
            />
          </Col>
          <Col span={12}>
            <Select
              value={filterType}
              onChange={setFilterType}
              style={{ width: '100%' }}
              placeholder="过滤类型"
            >
              <Select.Option value="all">全部文件</Select.Option>
              <Select.Option value="selected">已选文件</Select.Option>
              <Select.Option value="analyzed">已分析</Select.Option>
              <Select.Option value="code">代码文件</Select.Option>
              <Select.Option value="config">配置文件</Select.Option>
            </Select>
          </Col>
        </Row>

        {/* 统计信息 */}
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="总文件数"
                value={stats.totalFiles}
                prefix={<FileOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="已选文件"
                value={stats.selectedFiles}
                prefix={<Checkbox />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="已分析"
                value={stats.analyzedFiles}
                prefix={<BulbOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="总大小"
                value={formatFileSize(stats.totalSize)}
                prefix={<DatabaseOutlined />}
              />
            </Card>
          </Col>
        </Row>

        {/* 扫描进度 */}
        {isScanning && (
          <Card size="small" style={{ marginBottom: 16 }}>
            <Progress 
              percent={scanProgress} 
              status="active"
              format={percent => `扫描中... ${percent}%`}
            />
          </Card>
        )}

        {/* 文件树 */}
        <Card size="small">
          <DirectoryTree
            multiple
            treeData={filteredTreeData.map(node => ({
              ...node,
              title: renderNodeTitle(node)
            }))}
            expandedKeys={expandedKeys}
            selectedKeys={selectedKeys}
            onExpand={(keys) => setExpandedKeys(keys as string[])}
            onSelect={(keys) => {
              setSelectedKeys(keys as string[]);
              const selectedFiles = getSelectedFiles();
              onFilesSelected(selectedFiles);
            }}
            height={400}
            style={{ backgroundColor: '#fafafa' }}
          />
        </Card>
      </Card>

      {/* 扫描配置模态框 */}
      <Modal
        title="目录扫描配置"
        open={showConfigModal}
        onCancel={() => setShowConfigModal(false)}
        footer={null}
        width={600}
      >
        {/* 配置表单内容 */}
        <div>
          <h4>扫描选项</h4>
          {/* 这里可以添加具体的配置表单 */}
          <p>最大深度: {scanConfig.maxDepth}</p>
          <p>包含隐藏文件: {scanConfig.includeHidden ? '是' : '否'}</p>
          <p>自动分析: {scanConfig.autoAnalyze ? '是' : '否'}</p>
        </div>
      </Modal>
    </div>
  );
};

export default InteractiveFileTree;
