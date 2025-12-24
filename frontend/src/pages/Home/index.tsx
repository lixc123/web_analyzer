import React, { useEffect } from 'react'
import { Card, Row, Col, Statistic, Progress, Typography, Space, Button, Alert } from 'antd'
import {
  BugOutlined,
  BarChartOutlined,
  RobotOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  SyncOutlined
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { useGlobalStore } from '@store/GlobalStore'
import { systemApi } from '@services/api'

const { Title, Paragraph } = Typography

const HomePage: React.FC = () => {
  const { updateSystemStatus } = useGlobalStore()

  // 获取系统状态
  const { data: healthData, isLoading: healthLoading, refetch: refetchHealth } = useQuery({
    queryKey: ['system-health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30000, // 30秒刷新一次
  })

  // 获取系统统计
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['system-stats'],
    queryFn: systemApi.getStats,
    refetchInterval: 60000, // 1分钟刷新一次
  })

  // 更新全局系统状态
  useEffect(() => {
    if (healthData) {
      updateSystemStatus({
        backend: healthData.status === 'healthy' ? 'healthy' : 'unhealthy'
      })
    }
  }, [healthData, updateSystemStatus])

  const renderSystemStatus = () => {
    if (healthLoading) {
      return (
        <Alert
          title="正在检查系统状态..."
          type="info"
          showIcon
          icon={<SyncOutlined spin />}
        />
      )
    }

    if (!healthData || healthData.status !== 'healthy') {
      return (
        <Alert
          title="系统状态异常"
          description="部分服务可能不可用，请检查系统配置"
          type="error"
          showIcon
          icon={<ExclamationCircleOutlined />}
          action={
            <Button size="small" onClick={() => refetchHealth()}>
              重新检查
            </Button>
          }
        />
      )
    }

    return (
      <Alert
        title="系统运行正常"
        description="所有服务已就绪，可以开始使用"
        type="success"
        showIcon
        icon={<CheckCircleOutlined />}
      />
    )
  }

  return (
    <div className="page-container">
      {/* 页面头部 */}
      <div className="page-header">
        <div>
          <Title level={2} className="page-title">系统概览</Title>
          <Paragraph className="page-description">
            Web Analyzer V2 - 现代化网络流量分析平台
          </Paragraph>
        </div>
        <Button type="primary" onClick={() => refetchHealth()}>
          刷新状态
        </Button>
      </div>

      {/* 系统状态警告 */}
      <div className="mb-24">
        {renderSystemStatus()}
      </div>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]} className="mb-24">
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="活跃会话"
              value={statsData?.sessions?.active || 0}
              prefix={<BugOutlined style={{ color: '#1890ff' }} />}
              suffix="个"
            />
            <div className="stat-trend positive">
              +{statsData?.sessions?.today || 0} 今日新增
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="已录制请求"
              value={statsData?.requests?.total || 0}
              prefix={<BarChartOutlined style={{ color: '#52c41a' }} />}
              suffix="条"
            />
            <div className="stat-trend positive">
              +{statsData?.requests?.today || 0} 今日新增
            </div>
          </Card>
        </Col>


        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="可疑请求"
              value={statsData?.suspicious?.count || 0}
              prefix={<ExclamationCircleOutlined style={{ color: '#f5222d' }} />}
              suffix="条"
            />
            <div className={`stat-trend ${(statsData?.suspicious?.trend || 0) > 0 ? 'negative' : 'positive'}`}>
              {(statsData?.suspicious?.trend || 0) >= 0 ? '+' : ''}{statsData?.suspicious?.trend || 0} 较昨日
            </div>
          </Card>
        </Col>
      </Row>

      {/* 详细信息面板 */}
      <Row gutter={[16, 16]}>
        {/* 服务状态 */}
        <Col xs={24} lg={12}>
          <Card title="服务状态" loading={healthLoading}>
            <Space orientation="vertical" style={{ width: '100%' }}>
              <div className="flex-between">
                <span>FastAPI 后端</span>
                <div>
                  <span className={`status-dot ${healthData?.status === 'healthy' ? 'success' : 'error'}`}></span>
                  <span>{healthData?.status === 'healthy' ? '运行中' : '异常'}</span>
                </div>
              </div>

              <div className="flex-between">
                <span>Qwen-Code 服务</span>
                <div>
                  <span className={`status-dot ${healthData?.services?.qwen === 'ready' ? 'success' : 'error'}`}></span>
                  <span>{healthData?.services?.qwen === 'ready' ? '就绪' : '未就绪'}</span>
                </div>
              </div>


              <div className="flex-between">
                <span>向量数据库</span>
                <div>
                  <span className={`status-dot ${healthData?.services?.embedding === 'ready' ? 'success' : 'warning'}`}></span>
                  <span>{healthData?.services?.embedding === 'ready' ? '活跃' : '待机'}</span>
                </div>
              </div>
            </Space>
          </Card>
        </Col>

        {/* 系统资源 */}
        <Col xs={24} lg={12}>
          <Card title="系统资源" loading={statsLoading}>
            <Space orientation="vertical" style={{ width: '100%' }}>
              <div>
                <div className="flex-between mb-8">
                  <span>内存使用率</span>
                  <span>{statsData?.resources?.memory || 0}%</span>
                </div>
                <Progress 
                  percent={statsData?.resources?.memory || 0}
                  status={statsData?.resources?.memory > 80 ? 'exception' : 'normal'}
                  size="small"
                />
              </div>

              <div>
                <div className="flex-between mb-8">
                  <span>CPU 使用率</span>
                  <span>{statsData?.resources?.cpu || 0}%</span>
                </div>
                <Progress 
                  percent={statsData?.resources?.cpu || 0}
                  status={statsData?.resources?.cpu > 80 ? 'exception' : 'normal'}
                  size="small"
                />
              </div>

              <div>
                <div className="flex-between mb-8">
                  <span>磁盘使用率</span>
                  <span>{statsData?.resources?.disk || 0}%</span>
                </div>
                <Progress 
                  percent={statsData?.resources?.disk || 0}
                  status={statsData?.resources?.disk > 90 ? 'exception' : 'normal'}
                  size="small"
                />
              </div>

              <div>
                <div className="flex-between mb-8">
                  <span>网络连接</span>
                  <span>{statsData?.resources?.connections || 0} 个</span>
                </div>
                <Progress 
                  percent={Math.min((statsData?.resources?.connections || 0) / 100 * 100, 100)}
                  showInfo={false}
                  size="small"
                />
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* 快捷操作 */}
      <Card title="快捷操作" className="mt-24">
        <Space wrap>
          <Button type="primary" icon={<BugOutlined />} href="/crawler">
            开始爬虫录制
          </Button>
          <Button icon={<BarChartOutlined />} href="/analysis">
            查看数据分析
          </Button>
          <Button icon={<RobotOutlined />} href="/ai">
            AI 智能分析
          </Button>
          <Button icon={<CheckCircleOutlined />} onClick={() => refetchHealth()}>
            检查系统状态
          </Button>
        </Space>
      </Card>
    </div>
  )
}

export default HomePage
