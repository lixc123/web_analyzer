import React, { useEffect, useRef, useState } from 'react';
import { Card, Button, Space, message, Spin, Modal, Descriptions } from 'antd';
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

const DependencyGraph: React.FC = () => {
  const cyRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(false);
  const [cy, setCy] = useState<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<DependencyNode | null>(null);
  const [showNodeDetail, setShowNodeDetail] = useState(false);

  const loadDependencyGraph = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/analysis/dependency-graph', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests: [] })
      });

      if (response.ok) {
        const data: DependencyGraphData = await response.json();
        renderGraph(data);
        message.success('依赖关系图加载成功');
      }
    } catch (error) {
      message.error('加载失败: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  };

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
    loadDependencyGraph();
  }, []);

  return (
    <>
      <Card title="请求依赖关系图">
        <Space style={{ marginBottom: 16 }}>
          <Button onClick={loadDependencyGraph} loading={loading}>
            刷新图形
          </Button>
          <Button onClick={() => cy?.fit()}>
            适应窗口
          </Button>
          <Button onClick={() => cy?.reset()}>
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
