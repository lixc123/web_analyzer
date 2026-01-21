import React from 'react'
import { Card, Collapse, Typography, Space, Tag, Divider, Steps, Alert } from 'antd'
import {
  QuestionCircleOutlined,
  RocketOutlined,
  ToolOutlined,
  BugOutlined,
  CodeOutlined,
  ThunderboltOutlined
} from '@ant-design/icons'

const { Title, Text, Paragraph } = Typography
const { Panel } = Collapse

const HelpGuide: React.FC = () => {
  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <Card>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <div style={{ textAlign: 'center' }}>
            <Title level={2}>
              <QuestionCircleOutlined /> Web分析工具使用指南
            </Title>
            <Text type="secondary">快速上手，掌握所有功能</Text>
          </div>

          <Alert
            message="欢迎使用Web分析工具！"
            description="这是一个功能强大的Web流量分析和爬虫开发工具，支持代理抓包、请求分析、代码生成、Native Hook等多种功能。"
            type="success"
            showIcon
          />

          <Divider orientation="left">
            <RocketOutlined /> 快速开始
          </Divider>

          <Steps
            direction="vertical"
            current={-1}
            items={[
              {
                title: '步骤1：启动代理服务',
                description: (
                  <div>
                    <Paragraph>
                      进入<Tag color="blue">代理录制</Tag>页面，点击"启动代理"按钮。
                    </Paragraph>
                    <Paragraph>
                      系统将在本地启动HTTP/HTTPS代理服务器（默认端口8080）。
                    </Paragraph>
                  </div>
                )
              },
              {
                title: '步骤2：配置设备代理',
                description: (
                  <div>
                    <Paragraph>
                      在<Tag color="green">移动端配置</Tag>标签页中，扫描二维码或手动配置代理。
                    </Paragraph>
                    <Paragraph>
                      • 代理地址：显示的本机IP<br />
                      • 代理端口：8080<br />
                      • 安装CA证书以支持HTTPS抓包
                    </Paragraph>
                  </div>
                )
              },
              {
                title: '步骤3：开始录制',
                description: (
                  <div>
                    <Paragraph>
                      进入<Tag color="purple">爬虫录制</Tag>页面，创建新会话并开始录制。
                    </Paragraph>
                    <Paragraph>
                      在浏览器或APP中操作，系统将自动捕获所有HTTP/HTTPS请求。
                    </Paragraph>
                  </div>
                )
              },
              {
                title: '步骤4：分析和生成代码',
                description: (
                  <div>
                    <Paragraph>
                      录制完成后，可以：
                    </Paragraph>
                    <Paragraph>
                      • 在<Tag color="orange">数据分析</Tag>页面分析请求特征<br />
                      • 在<Tag color="cyan">代码生成</Tag>页面生成Python/JavaScript代码<br />
                      • 在<Tag color="red">请求录制</Tag>页面重放请求
                    </Paragraph>
                  </div>
                )
              }
            ]}
          />

          <Divider orientation="left">
            <ToolOutlined /> 功能详解
          </Divider>

          <Collapse defaultActiveKey={['1']}>
            <Panel header="🌐 代理抓包" key="1">
              <Paragraph>
                <Text strong>功能说明：</Text>启动本地代理服务器，拦截并记录HTTP/HTTPS流量。
              </Paragraph>
              <Paragraph>
                <Text strong>主要特性：</Text>
                <ul>
                  <li>支持HTTP/HTTPS协议</li>
                  <li>自动生成和安装CA证书</li>
                  <li>实时显示请求列表</li>
                  <li>支持多设备同时连接</li>
                  <li>请求详情查看和导出</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>移动APP抓包、Web应用分析、API接口调试
              </Paragraph>
            </Panel>

            <Panel header="🕷️ 爬虫录制" key="2">
              <Paragraph>
                <Text strong>功能说明：</Text>使用Playwright自动化浏览器，录制网页操作和请求。
              </Paragraph>
              <Paragraph>
                <Text strong>主要特性：</Text>
                <ul>
                  <li>支持Chrome、Firefox、Safari浏览器</li>
                  <li>自动录制HTTP请求和响应</li>
                  <li>捕获JavaScript调用栈</li>
                  <li>支持无头模式和有头模式</li>
                  <li>会话管理和导出</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>网页爬虫开发、自动化测试、数据采集
              </Paragraph>
            </Panel>

            <Panel header="📊 数据分析" key="3">
              <Paragraph>
                <Text strong>功能说明：</Text>智能分析网络流量，识别加密参数和敏感信息。
              </Paragraph>
              <Paragraph>
                <Text strong>分析类型：</Text>
                <ul>
                  <li><Text strong>熵值分析：</Text>检测高熵字段（可能的加密数据）</li>
                  <li><Text strong>敏感参数：</Text>识别密码、令牌等敏感信息</li>
                  <li><Text strong>加密关键词：</Text>查找加密相关的参数名</li>
                  <li><Text strong>结果比较：</Text>对比多次分析结果的差异</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>API逆向工程、安全审计、加密算法定位
              </Paragraph>
            </Panel>

            <Panel header="💻 代码生成" key="4">
              <Paragraph>
                <Text strong>功能说明：</Text>将录制的请求自动转换为可执行的爬虫代码。
              </Paragraph>
              <Paragraph>
                <Text strong>支持语言：</Text>
                <ul>
                  <li>Python (requests库)</li>
                  <li>JavaScript (axios库)</li>
                  <li>cURL命令</li>
                  <li>Java (开发中)</li>
                  <li>Go (开发中)</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>功能特性：</Text>
                <ul>
                  <li>代码预览和语法高亮</li>
                  <li>一键下载生成的代码</li>
                  <li>批量生成多个会话</li>
                  <li>会话统计信息查看</li>
                </ul>
              </Paragraph>
            </Panel>

            <Panel header="🎯 请求录制" key="5">
              <Paragraph>
                <Text strong>功能说明：</Text>独立的请求录制和重放工具。
              </Paragraph>
              <Paragraph>
                <Text strong>主要特性：</Text>
                <ul>
                  <li>手动开始/停止录制</li>
                  <li>查看请求详情（头、体、响应）</li>
                  <li>修改请求参数后重放</li>
                  <li>支持SSL验证开关</li>
                  <li>请求统计和分析</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>API测试、请求调试、参数篡改测试
              </Paragraph>
            </Panel>

            <Panel header="⚡ Native Hook" key="6">
              <Paragraph>
                <Text strong>功能说明：</Text>使用Frida框架Hook Windows应用程序。
              </Paragraph>
              <Paragraph>
                <Text strong>主要特性：</Text>
                <ul>
                  <li>进程列表和附加</li>
                  <li>内置Hook脚本模板</li>
                  <li>自定义Frida脚本</li>
                  <li>实时查看Hook记录</li>
                  <li>支持多进程同时Hook</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>桌面应用逆向、加密算法提取、行为分析
              </Paragraph>
            </Panel>

            <Panel header="🤖 AI终端" key="7">
              <Paragraph>
                <Text strong>功能说明：</Text>集成Qwen AI模型的智能分析助手。
              </Paragraph>
              <Paragraph>
                <Text strong>主要特性：</Text>
                <ul>
                  <li>自然语言交互</li>
                  <li>代码分析和解释</li>
                  <li>问题诊断和建议</li>
                  <li>会话历史管理</li>
                </ul>
              </Paragraph>
              <Paragraph>
                <Text strong>使用场景：</Text>代码理解、问题排查、学习辅助
              </Paragraph>
            </Panel>
          </Collapse>

          <Divider orientation="left">
            <BugOutlined /> 常见问题
          </Divider>

          <Collapse>
            <Panel header="Q: HTTPS抓包显示证书错误？" key="faq1">
              <Paragraph>
                <Text strong>解决方案：</Text>
                <ol>
                  <li>在"代理录制"页面下载CA证书</li>
                  <li>在设备上安装证书（参考"证书管理"标签页的说明）</li>
                  <li>确保证书已被信任</li>
                  <li>重启浏览器或APP</li>
                </ol>
              </Paragraph>
            </Panel>

            <Panel header="Q: 移动设备无法连接代理？" key="faq2">
              <Paragraph>
                <Text strong>检查清单：</Text>
                <ol>
                  <li>确保设备和电脑在同一局域网</li>
                  <li>检查防火墙是否允许8080端口</li>
                  <li>确认代理地址和端口配置正确</li>
                  <li>尝试重启代理服务</li>
                </ol>
              </Paragraph>
            </Panel>

            <Panel header="Q: 生成的代码无法运行？" key="faq3">
              <Paragraph>
                <Text strong>可能原因：</Text>
                <ul>
                  <li>缺少依赖库：安装 requests 或 axios</li>
                  <li>请求头不完整：手动补充必要的请求头</li>
                  <li>需要登录态：先获取有效的Cookie或Token</li>
                  <li>反爬虫机制：需要添加延时或代理</li>
                </ul>
              </Paragraph>
            </Panel>

            <Panel header="Q: Frida Hook失败？" key="faq4">
              <Paragraph>
                <Text strong>解决方案：</Text>
                <ol>
                  <li>确保已安装Frida：pip install frida frida-tools</li>
                  <li>检查目标进程是否有反调试保护</li>
                  <li>尝试以管理员权限运行</li>
                  <li>查看错误日志获取详细信息</li>
                </ol>
              </Paragraph>
            </Panel>
          </Collapse>

          <Divider orientation="left">
            <CodeOutlined /> 最佳实践
          </Divider>

          <Card size="small">
            <Paragraph>
              <Text strong>1. 爬虫开发流程：</Text>
              <ol>
                <li>使用"爬虫录制"功能录制目标网站的操作</li>
                <li>在"数据分析"中识别关键API和参数</li>
                <li>使用"代码生成"生成初始代码</li>
                <li>根据需求修改和优化代码</li>
                <li>使用"请求录制"测试和调试</li>
              </ol>
            </Paragraph>

            <Paragraph>
              <Text strong>2. API逆向分析：</Text>
              <ol>
                <li>使用"代理抓包"捕获APP的网络请求</li>
                <li>在"数据分析"中进行熵值分析，定位加密参数</li>
                <li>使用"Native Hook"定位加密算法</li>
                <li>使用"AI终端"辅助理解加密逻辑</li>
                <li>编写解密代码并测试</li>
              </ol>
            </Paragraph>

            <Paragraph>
              <Text strong>3. 性能优化建议：</Text>
              <ul>
                <li>录制时避免打开过多标签页</li>
                <li>定期清理旧的会话数据</li>
                <li>大量请求时使用过滤功能</li>
                <li>批量操作时使用后台任务</li>
              </ul>
            </Paragraph>
          </Card>

          <Alert
            message="需要更多帮助？"
            description={
              <div>
                <Paragraph>
                  • 查看项目文档：<Text code>README.md</Text><br />
                  • 提交问题：GitHub Issues<br />
                  • 加入社区：Discord / QQ群
                </Paragraph>
              </div>
            }
            type="info"
            showIcon
            icon={<ThunderboltOutlined />}
          />
        </Space>
      </Card>
    </div>
  )
}

export default HelpGuide
