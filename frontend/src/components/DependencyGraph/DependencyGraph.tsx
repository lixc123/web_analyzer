import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Card, Button, Space, message, Spin, Modal, Descriptions, Alert } from 'antd';
import cytoscape from 'cytoscape';

interface DependencyNode {
  id: string;
  label: string;
  type: string;
  method?: string;
  url?: string;
}

interface DependencyEdge {
  source: string;
  target: string;
  label?: string;
}

interface DependencyGraphData {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
}

interface DependencyGraphProps {
  sessionId?: string;
  requests?: any[];
}

const DependencyGraph: React.FC<DependencyGraphProps> = ({ sessionId, requests: propRequests }) => {
  const cyRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(false);
  const [cy, setCy] = useState<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<DependencyNode | null>(null);
  const [showNodeDetail, setShowNodeDetail] = useState(false);

  const loadDependencyGraph = useCallback(async () => {
    try {
      setLoading(true);
      
      // 构建请求体：优先使用sessionId，其次使用propRequests
      let requestBody: any;
      
      if (sessionId) {
        // 如果有sessionId，使用session_id参数
        requestBody = { session_id: sessionId };
      } else if (propRequests && propRequests.length > 0) {
        // 如果有requests数组，使用requests参数
        requestBody = { requests: propRequests };
      } else {
        // 如果都没有，显示警告并返回
        message.warning('请提供sessionId或requests数据以生成依赖图');
        setLoading(false);
        return;
      }
      
      const response = await fetch('/api/v1/analysis/dependency-graph', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const data: DependencyGraphData = await response.json();
        
        // 检查是否有数据
        if (!data.nodes || data.nodes.length === 0) {
          message.info('当前会话没有足够的数据生成依赖图');
        } else {
          renderGraph(data);
          message.success(`依赖关系图加载成功，包含 ${data.nodes.length} 个节点`);
        }
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || '加载失败');
      }
    } catch (error) {
      message.error('加载失败: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  }, [sessionId, propRequests]);

  const renderGraph = (data: DependencyGraphData) => {
    if (!cyRef.current) return;

    const elements = [
      ...data.nodes.map(node => ({
        data: { id: node.id, label: node.label, type: node.type, method: node.method, url: node.url }
      })),
      ...data.edges.map(edge => ({
        data: { source: edge.source, target: edge.target, label: edge.label }
      }))
    ];

    const cyInstance = cytoscape({
      container: cyRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#1890ff',
            'label': 'data(label)',
            'color': '#fff',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 80,
            'height': 80,
            'font-size': '12px'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#ccc',
            'target-arrow-color': '#ccc',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '10px'
          }
        },
        {
          selector: 'node:selected',
          style: {
            'background-color': '#ff4d4f',
            'border-width': 3,
            'border-color': '#ff7875'
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 30,
        spacingFactor: 1.5
      }
    });

    cyInstance.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode(node.data());
      setShowNodeDetail(true);
    });

    setCy(cyInstance);
  };

  useEffect(() => {
    // 只有在有sessionId或requests时才加载
    if (sessionId || (propRequests && propRequests.length > 0)) {
      loadDependencyGraph();
    }
  }, [sessionId, propRequests, loadDependencyGraph]);

  return (
    <>
      <Card title="请求依赖关系图">
        {!sessionId && (!propRequests || propRequests.length === 0) && (
          <Alert
            message="提示"
            description="请提供sessionId或requests数据以生成依赖关系图"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        <Space style={{ marginBottom: 16 }}>
          <Button 
            onClick={loadDependencyGraph} 
            loading={loading}
            disabled={!sessionId && (!propRequests || propRequests.length === 0)}
          >
            刷新图形
          </Button>
          <Button onClick={() => cy?.fit()} disabled={!cy}>
            适应窗口
          </Button>
          <Button onClick={() => cy?.reset()} disabled={!cy}>
            重置视图
          </Button>
        </Space>
        <Spin spinning={loading}>
          <div ref={cyRef} style={{ width: '100%', height: '600px', border: '1px solid #d9d9d9', borderRadius: 4 }} />
        </Spin>
      </Card>

      <Modal
        title="节点详情"
        open={showNodeDetail}
        onCancel={() => setShowNodeDetail(false)}
        footer={null}
      >
        {selectedNode && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="ID">{selectedNode.id}</Descriptions.Item>
            <Descriptions.Item label="标签">{selectedNode.label}</Descriptions.Item>
            <Descriptions.Item label="类型">{selectedNode.type}</Descriptions.Item>
            {selectedNode.method && <Descriptions.Item label="方法">{selectedNode.method}</Descriptions.Item>}
            {selectedNode.url && <Descriptions.Item label="URL">{selectedNode.url}</Descriptions.Item>}
          </Descriptions>
        )}
      </Modal>
    </>
  );
};

export default DependencyGraph;
