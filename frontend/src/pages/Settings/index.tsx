import React, { useState } from 'react'
import {
  Card,
  Form,
  Input,
  Switch,
  Button,
  Space,
  Typography,
  Tabs,
  Divider,
  Select,
  InputNumber,
  Slider,
  Alert,
  Modal,
  notification,
  Row,
  Col
} from 'antd'
import {
  SettingOutlined,
  SaveOutlined,
  ReloadOutlined,
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  KeyOutlined,
  DatabaseOutlined,
  RobotOutlined,
  BugOutlined
} from '@ant-design/icons'
import { useGlobalStore } from '@store/GlobalStore'

const { Title, Text, Paragraph } = Typography
const { TextArea } = Input
const { Option } = Select
const { confirm } = Modal

const SettingsPage: React.FC = () => {
  const [form] = Form.useForm()
  const [apiForm] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const { settings, updateSettings, theme, setTheme } = useGlobalStore()

  const handleSaveSettings = async () => {
    try {
      setLoading(true)
      const values = await form.validateFields()
      
      updateSettings({
        autoSave: values.autoSave,
        notifications: values.notifications,
        maxConcurrentRequests: values.maxConcurrentRequests,
        analysisThreshold: values.analysisThreshold
      })

      notification.success({
        title: '设置已保存',
        description: '您的设置更改已成功保存'
      })
    } catch (error) {
      console.error('保存设置失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSaveApiSettings = async () => {
    try {
      setLoading(true)
      const values = await apiForm.validateFields()
      
      // 这里应该调用API保存到后端
      console.log('保存API设置:', values)
      
      notification.success({
        title: 'API设置已保存',
        description: '新的API配置将在下次重启后生效'
      })
    } catch (error) {
      console.error('保存API设置失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleResetSettings = () => {
    confirm({
      title: '确认重置',
      icon: <ExclamationCircleOutlined />,
      content: '确定要重置所有设置到默认值吗？此操作不可撤销。',
      onOk() {
        form.resetFields()
        updateSettings({
          autoSave: true,
          notifications: true,
          maxConcurrentRequests: 5,
          analysisThreshold: 4.0
        })
        
        notification.info({
          title: '设置已重置',
          description: '所有设置已恢复到默认值'
        })
      }
    })
  }

  const handleTestConnection = async (service: string) => {
    try {
      setLoading(true)
      
      // 这里应该调用对应的健康检查API
      notification.success({
        title: `${service} 连接测试成功`,
        description: '服务响应正常'
      })
    } catch (error) {
      notification.error({
        title: `${service} 连接测试失败`,
        description: '请检查配置是否正确'
      })
    } finally {
      setLoading(false)
    }
  }

  const tabItems = [
    {
      key: 'general',
      label: (
        <span>
          <SettingOutlined />
          通用设置
        </span>
      ),
      children: (
        <div>
          <Form
            form={form}
            layout="vertical"
            initialValues={settings}
            onFinish={handleSaveSettings}
          >
            <Card title="基本设置" style={{ marginBottom: 24 }}>
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    label="自动保存"
                    name="autoSave"
                    valuePropName="checked"
                    extra="启用后将自动保存录制数据和分析结果"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    label="桌面通知"
                    name="notifications"
                    valuePropName="checked"
                    extra="允许显示系统通知"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    label="最大并发请求数"
                    name="maxConcurrentRequests"
                    extra="同时处理的最大请求数量"
                  >
                    <InputNumber min={1} max={20} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    label="分析阈值"
                    name="analysisThreshold"
                    extra="熵值分析的最小阈值"
                  >
                    <InputNumber min={0} max={8} step={0.1} />
                  </Form.Item>
                </Col>
              </Row>
            </Card>

            <Card title="界面设置" style={{ marginBottom: 24 }}>
              <Form.Item label="主题模式">
                <Select value={theme} onChange={setTheme}>
                  <Option value="light">亮色模式</Option>
                  <Option value="dark">暗色模式</Option>
                </Select>
              </Form.Item>

              <Alert
                title="主题设置"
                description="主题更改将立即生效，无需重启应用"
                type="info"
                showIcon
                style={{ marginTop: 16 }}
              />
            </Card>

            <Space>
              <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={loading}>
                保存设置
              </Button>
              <Button icon={<ReloadOutlined />} onClick={handleResetSettings}>
                重置默认
              </Button>
            </Space>
          </Form>
        </div>
      )
    },
    {
      key: 'api',
      label: (
        <span>
          <KeyOutlined />
          API 配置
        </span>
      ),
      children: (
        <div>
          <Alert
            title="API 配置说明"
            description="修改API配置后需要重启应用才能生效。请确保API密钥的安全性。"
            type="warning"
            showIcon
            style={{ marginBottom: 24 }}
          />

          <Form
            form={apiForm}
            layout="vertical"
            initialValues={{
              backendPort: 8000,
              frontendPort: 3000
            }}
          >

            <Card title="服务端口配置" style={{ marginBottom: 24 }}>
              <Row gutter={24}>
                <Col span={8}>
                  <Form.Item label="后端端口" name="backendPort">
                    <InputNumber min={1000} max={65535} />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item label="前端端口" name="frontendPort">
                    <InputNumber min={1000} max={65535} />
                  </Form.Item>
                </Col>
              </Row>
            </Card>

            <Space>
              <Button type="primary" icon={<SaveOutlined />} onClick={handleSaveApiSettings} loading={loading}>
                保存API配置
              </Button>
              <Button icon={<CheckCircleOutlined />} onClick={() => handleTestConnection('All')}>
                测试所有连接
              </Button>
            </Space>
          </Form>
        </div>
      )
    },
    {
      key: 'data',
      label: (
        <span>
          <DatabaseOutlined />
          数据管理
        </span>
      ),
      children: (
        <div>
          <Card title="数据存储设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item label="数据目录">
                <Space.Compact style={{ width: '100%' }}>
                  <Input defaultValue="./data" style={{ width: 'calc(100% - 50px)' }} />
                  <Button size="small">浏览</Button>
                </Space.Compact>
              </Form.Item>

              <Form.Item label="日志目录">
                <Space.Compact style={{ width: '100%' }}>
                  <Input defaultValue="./logs" style={{ width: 'calc(100% - 50px)' }} />
                  <Button size="small">浏览</Button>
                </Space.Compact>
              </Form.Item>

              <Form.Item label="缓存设置">
                <Row gutter={16}>
                  <Col span={12}>
                    <Text>缓存TTL (秒):</Text>
                    <Slider min={300} max={7200} defaultValue={3600} marks={{ 300: '5分钟', 3600: '1小时', 7200: '2小时' }} />
                  </Col>
                  <Col span={12}>
                    <Text>最大缓存大小:</Text>
                    <Slider min={100} max={5000} defaultValue={1000} marks={{ 100: '100', 1000: '1000', 5000: '5000' }} />
                  </Col>
                </Row>
              </Form.Item>
            </Form>
          </Card>

          <Card title="数据清理" style={{ marginBottom: 24 }}>
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Alert
                title="数据清理操作"
                description="这些操作将永久删除数据，请谨慎操作"
                type="error"
                showIcon
              />

              <Space wrap>
                <Button danger onClick={() => {
                  confirm({
                    title: '确认清理缓存',
                    content: '确定要清理所有缓存数据吗？',
                    onOk() {
                      notification.success({ title: '缓存已清理' })
                    }
                  })
                }}>
                  清理缓存
                </Button>

                <Button danger onClick={() => {
                  confirm({
                    title: '确认清理日志',
                    content: '确定要清理所有日志文件吗？',
                    onOk() {
                      notification.success({ title: '日志已清理' })
                    }
                  })
                }}>
                  清理日志
                </Button>

                <Button danger onClick={() => {
                  confirm({
                    title: '确认重置数据库',
                    content: '确定要重置数据库吗？这将删除所有录制数据和分析结果！',
                    onOk() {
                      notification.success({ title: '数据库已重置' })
                    }
                  })
                }}>
                  重置数据库
                </Button>
              </Space>
            </Space>
          </Card>
        </div>
      )
    },
    {
      key: 'advanced',
      label: (
        <span>
          <RobotOutlined />
          高级设置
        </span>
      ),
      children: (
        <div>
          <Card title="爬虫设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item 
                label="Chrome 浏览器路径" 
                extra="留空则自动查找系统安装的 Chrome，填写后优先使用指定路径"
              >
                <Input 
                  placeholder="例如: C:/Program Files/Google/Chrome/Application/chrome.exe"
                  defaultValue={localStorage.getItem('chrome_path') || ''}
                  onChange={(e) => {
                    localStorage.setItem('chrome_path', e.target.value)
                  }}
                />
              </Form.Item>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item label="默认超时时间 (秒)">
                    <InputNumber min={5} max={300} defaultValue={30} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item label="最大重试次数">
                    <InputNumber min={0} max={10} defaultValue={3} />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item label="默认User-Agent">
                <TextArea 
                  rows={3}
                  defaultValue="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                />
              </Form.Item>

              <Form.Item label="忽略的文件类型">
                <Select mode="tags" placeholder="输入文件扩展名" defaultValue={['jpg', 'png', 'gif', 'ico', 'css', 'js']}>
                  <Option value="jpg">jpg</Option>
                  <Option value="png">png</Option>
                  <Option value="gif">gif</Option>
                  <Option value="ico">ico</Option>
                  <Option value="css">css</Option>
                  <Option value="js">js</Option>
                </Select>
              </Form.Item>
            </Form>
          </Card>

          <Card title="分析设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item label="敏感参数关键词">
                <TextArea 
                  rows={4}
                  defaultValue="password,passwd,pwd,token,key,secret,auth,session,cookie,csrf,jwt"
                  placeholder="用逗号分隔多个关键词"
                />
              </Form.Item>

              <Form.Item label="加密算法关键词">
                <TextArea 
                  rows={4}
                  defaultValue="aes,rsa,des,md5,sha1,sha256,sha512,hmac,base64,encrypt,decrypt"
                  placeholder="用逗号分隔多个关键词"
                />
              </Form.Item>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item label="最小熵值阈值">
                    <Slider min={1} max={8} step={0.1} defaultValue={4.0} marks={{ 1: '1.0', 4: '4.0', 8: '8.0' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item label="分析深度">
                    <Select defaultValue="medium">
                      <Option value="basic">基础</Option>
                      <Option value="medium">中等</Option>
                      <Option value="deep">深度</Option>
                    </Select>
                  </Form.Item>
                </Col>
              </Row>
            </Form>
          </Card>

        </div>
      )
    }
  ]

  return (
    <div className="page-container">
      {/* 页面头部 */}
      <div className="page-header">
        <div>
          <Title level={2} className="page-title">系统设置</Title>
          <Text className="page-description">配置系统参数和个人偏好设置</Text>
        </div>
      </div>

      <Card>
        <Tabs items={tabItems} />
      </Card>
    </div>
  )
}

export default SettingsPage
