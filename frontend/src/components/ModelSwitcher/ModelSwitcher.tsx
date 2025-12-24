import React, { useState, useEffect } from 'react';
import { Select, Button, Modal, Form, Input, Space, Typography, Tag, Alert } from 'antd';
import { SwapOutlined, SettingOutlined, EyeOutlined, CodeOutlined, RobotOutlined } from '@ant-design/icons';
import { useAuth, AuthType } from '../Auth/AuthProvider';

const { Text } = Typography;
const { Option } = Select;

// 模型类型定义
export interface ModelInfo {
  id: string;
  name: string;
  description: string;
  isVision?: boolean;
  provider: 'qwen' | 'openai' | 'custom';
  capabilities: string[];
  pricing?: {
    input: number;
    output: number;
  };
}

// 预定义模型列表
const PREDEFINED_MODELS: ModelInfo[] = [
  {
    id: 'coder-model',
    name: 'Qwen Coder',
    description: 'Qwen3-Coder-Plus 专业编程模型',
    provider: 'qwen',
    capabilities: ['代码生成', '代码分析', '重构', '调试'],
  },
  {
    id: 'vision-model',
    name: 'Qwen Vision',
    description: 'Qwen3-VL-Plus 视觉理解模型',
    provider: 'qwen',
    isVision: true,
    capabilities: ['图像理解', '代码分析', '界面分析', 'OCR'],
  },
  {
    id: 'gpt-4',
    name: 'GPT-4',
    description: 'OpenAI GPT-4 通用大模型',
    provider: 'openai',
    capabilities: ['通用对话', '代码生成', '分析推理'],
    pricing: { input: 0.03, output: 0.06 },
  },
  {
    id: 'gpt-4-vision-preview',
    name: 'GPT-4 Vision',
    description: 'OpenAI GPT-4 视觉模型',
    provider: 'openai',
    isVision: true,
    capabilities: ['图像理解', '通用对话', '视觉分析'],
    pricing: { input: 0.01, output: 0.03 },
  },
];

interface ModelSwitcherProps {
  currentModel?: string;
  onModelChange?: (modelId: string, reason?: string) => void;
  showVisionSwitch?: boolean;
}

export const ModelSwitcher: React.FC<ModelSwitcherProps> = ({
  currentModel,
  onModelChange,
  showVisionSwitch = true,
}) => {
  return (
    <div>
      <Alert
        title="AI功能已移除"
        description="此应用现在专注于网络流量分析，不再提供AI模型切换功能"
        type="info"
        showIcon
        style={{ margin: '8px 0' }}
      />
    </div>
  );
};

export default ModelSwitcher;
