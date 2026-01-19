import React, { useState } from 'react';
import ProxyControl from './ProxyControl';
import MobileSetup from './MobileSetup';
import CertManager from './CertManager';
import './ProxyCapture.css';

const ProxyCapture: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'control' | 'mobile' | 'cert'>('control');

  return (
    <div className="proxy-capture-page">
      <h1>代理抓包</h1>

      <div className="tabs">
        <button
          className={activeTab === 'control' ? 'active' : ''}
          onClick={() => setActiveTab('control')}
        >
          代理控制
        </button>
        <button
          className={activeTab === 'mobile' ? 'active' : ''}
          onClick={() => setActiveTab('mobile')}
        >
          移动端配置
        </button>
        <button
          className={activeTab === 'cert' ? 'active' : ''}
          onClick={() => setActiveTab('cert')}
        >
          证书管理
        </button>
      </div>

      <div className="tab-content">
        {activeTab === 'control' && <ProxyControl />}
        {activeTab === 'mobile' && <MobileSetup />}
        {activeTab === 'cert' && <CertManager />}
      </div>
    </div>
  );
};

export default ProxyCapture;
