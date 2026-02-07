import React from 'react'
import { List } from 'react-window'
import { Tag, Space, Button, Typography } from 'antd'
import { EyeOutlined, ThunderboltOutlined } from '@ant-design/icons'
import './VirtualRequestList.css'

const { Text } = Typography

interface Request {
  id: string
  method: string
  url: string
  status?: number
  timestamp: number
  [key: string]: any
}

interface VirtualRequestListProps {
  requests: Request[]
  onViewDetail?: (request: Request) => void
  onReplay?: (request: Request) => void
  height?: number
  itemHeight?: number
}

const VirtualRequestList: React.FC<VirtualRequestListProps> = ({
  requests,
  onViewDetail,
  onReplay,
  height = 600,
  itemHeight = 50
}) => {
  const methodColors: Record<string, string> = {
    GET: '#1890ff',
    POST: '#52c41a',
    PUT: '#faad14',
    DELETE: '#f5222d',
    PATCH: '#722ed1'
  }

  const getStatusColor = (status?: number) => {
    if (!status) return 'default'
    if (status >= 200 && status < 300) return 'success'
    if (status >= 300 && status < 400) return 'processing'
    if (status >= 400 && status < 500) return 'warning'
    return 'error'
  }

  const Row = ({ index, style, ariaAttributes }: any) => {
    const request = requests[index]

    return (
      <div
        {...ariaAttributes}
        style={{
          ...style,
          borderBottom: '1px solid #f0f0f0',
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          backgroundColor: index % 2 === 0 ? '#fafafa' : '#ffffff'
        }}
        className="virtual-request-row"
      >
        {/* 方法 */}
        <div style={{ width: '80px', flexShrink: 0 }}>
          <Tag
            color={methodColors[request.method] || 'default'}
            style={{ margin: 0, fontWeight: 'bold' }}
          >
            {request.method}
          </Tag>
        </div>

        {/* URL */}
        <div style={{ flex: 1, minWidth: 0, padding: '0 12px' }}>
          <Text
            ellipsis={{ tooltip: request.url }}
            style={{ fontSize: '12px', display: 'block' }}
          >
            {request.url}
          </Text>
        </div>

        {/* 状态码 */}
        <div style={{ width: '80px', flexShrink: 0, textAlign: 'center' }}>
          {request.status ? (
            <Tag color={getStatusColor(request.status)} style={{ margin: 0 }}>
              {request.status}
            </Tag>
          ) : (
            <Tag style={{ margin: 0 }}>-</Tag>
          )}
        </div>

        {/* 时间 */}
        <div style={{ width: '160px', flexShrink: 0, padding: '0 12px' }}>
          <Text type="secondary" style={{ fontSize: '11px' }}>
            {new Date(request.timestamp * 1000).toLocaleString('zh-CN', {
              month: '2-digit',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit'
            })}
          </Text>
        </div>

        {/* 操作 */}
        <div style={{ width: '140px', flexShrink: 0 }}>
          <Space size="small">
            {onViewDetail && (
              <Button
                type="link"
                size="small"
                icon={<EyeOutlined />}
                onClick={() => onViewDetail(request)}
                style={{ padding: '0 4px' }}
              >
                详情
              </Button>
            )}
            {onReplay && (
              <Button
                type="link"
                size="small"
                icon={<ThunderboltOutlined />}
                onClick={() => onReplay(request)}
                style={{ padding: '0 4px' }}
              >
                重放
              </Button>
            )}
          </Space>
        </div>
      </div>
    )
  }

  // 表头
  const Header = () => (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        padding: '0 16px',
        height: '40px',
        backgroundColor: '#fafafa',
        borderBottom: '2px solid #e8e8e8',
        fontWeight: 'bold',
        fontSize: '13px'
      }}
    >
      <div style={{ width: '80px', flexShrink: 0 }}>方法</div>
      <div style={{ flex: 1, minWidth: 0, padding: '0 12px' }}>URL</div>
      <div style={{ width: '80px', flexShrink: 0, textAlign: 'center' }}>状态码</div>
      <div style={{ width: '160px', flexShrink: 0, padding: '0 12px' }}>时间</div>
      <div style={{ width: '140px', flexShrink: 0 }}>操作</div>
    </div>
  )

  return (
    <div style={{ border: '1px solid #f0f0f0', borderRadius: '4px' }}>
      <Header />
      <List
        rowCount={requests.length}
        rowHeight={itemHeight}
        rowComponent={Row}
        rowProps={{}}
        style={{ height, width: '100%' }}
        overscanCount={5}
      />
    </div>
  )
}

export default VirtualRequestList
