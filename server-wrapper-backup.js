const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { spawn, exec } = require('child_process');
const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config({ path: '../.env' });

const app = express();
const PORT = process.env.QWEN_CODE_PORT || 3001;

// 中间件配置
app.use(helmet());
app.use(cors({
  origin: [`http://localhost:${process.env.FRONTEND_PORT || 3000}`, `http://localhost:${process.env.BACKEND_PORT || 8000}`],
  credentials: true
}));
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 全局状态
const activeSessions = new Map();
const analysisResults = new Map();

// 日志函数
const log = (message, level = 'INFO') => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level}] ${message}`);
};

const resolveQwenRepoRoot = () => {
  const triedRoots = [];

  const envRoot = (process.env.QWEN_REPO_ROOT || '').trim();
  if (envRoot) {
    triedRoots.push(envRoot);
    if (fs.existsSync(path.join(envRoot, 'package.json'))) {
      return { repoRoot: envRoot, triedRoots, source: 'env' };
    }
  }

  const candidateRoots = [
    // sibling of web_analyzer_v2 in this repo
    path.resolve(__dirname, '../../../qwen-code'),
    // previous attempt (kept for compatibility)
    path.resolve(__dirname, '../../qwen-code'),
    // in case this wrapper is relocated
    path.resolve(__dirname, '../../../../qwen-code')
  ];

  for (const root of candidateRoots) {
    triedRoots.push(root);
    if (fs.existsSync(path.join(root, 'package.json'))) {
      return { repoRoot: root, triedRoots, source: 'auto' };
    }
  }

  return { repoRoot: null, triedRoots, source: null };
};

const resolveQwenCliPath = () => {
  const triedPaths = [];

  const envPath = (process.env.QWEN_CLI_PATH || '').trim();
  if (envPath) {
    triedPaths.push(envPath);
    if (fs.existsSync(envPath)) {
      return { cliPath: envPath, triedPaths, source: 'env' };
    }
  }

  const { repoRoot, triedRoots } = resolveQwenRepoRoot();
  if (!repoRoot) {
    triedPaths.push(...triedRoots);
    return { cliPath: null, triedPaths, source: null };
  }

  const candidatePaths = [
    // Preferred: built CLI entry
    path.join(repoRoot, 'packages', 'cli', 'dist', 'index.js'),
    // Fallback: source runner (requires qwen-code dependencies installed)
    path.join(repoRoot, 'scripts', 'start.js')
  ];
  triedPaths.push(...candidatePaths);

  const cliPath = candidatePaths.find((p) => fs.existsSync(p)) || null;
  return { cliPath, triedPaths, source: cliPath ? 'auto' : null };
};

const getDefaultWorkingDir = () => {
  const envCwd = (process.env.QWEN_WORKING_DIR || '').trim();
  if (envCwd) {
    return envCwd;
  }
  return path.resolve(__dirname, '..');
};

const getQwenRepoRoot = () => {
  const { repoRoot } = resolveQwenRepoRoot();
  return repoRoot;
};

const isQwenStartScript = (cliPath) => {
  if (!cliPath) return false;
  return path.normalize(cliPath).endsWith(path.normalize(path.join('scripts', 'start.js')));
};

const buildQwenInvocation = (command, args = [], options = {}) => {
  const { cliPath, triedPaths } = resolveQwenCliPath();

  if (!cliPath) {
    const detail = `Qwen-Code CLI not found. Tried: ${triedPaths.join(', ')}`;
    return { error: new Error(detail), triedPaths };
  }

  const workspaceCwd = options.cwd || getDefaultWorkingDir();
  const repoRoot = getQwenRepoRoot();
  const spawnCwd = isQwenStartScript(cliPath) ? (repoRoot || workspaceCwd) : workspaceCwd;

  const cmd = String(command || '').trim();
  const fullArgs = cmd ? [cliPath, cmd, ...args] : [cliPath, ...args];

  const env = {
    ...process.env,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    OPENAI_BASE_URL: process.env.OPENAI_BASE_URL,
    OPENAI_MODEL: process.env.OPENAI_MODEL || 'qwen-code',
    QWEN_WORKING_DIR: process.env.QWEN_WORKING_DIR || workspaceCwd
  };

  return { cliPath, triedPaths, fullArgs, spawnCwd, env, workspaceCwd };
};

// Qwen-Code CLI 包装函数
const executeQwenCommand = async (command, args = [], options = {}) => {
  return new Promise((resolve, reject) => {
    const invocation = buildQwenInvocation(command, args, options);
    if (invocation.error) {
      log(invocation.error.message, 'ERROR');
      reject(invocation.error);
      return;
    }

    log(`Executing: node ${invocation.fullArgs.join(' ')}`, 'DEBUG');
    
    const child = spawn('node', invocation.fullArgs, {
      env: invocation.env,
      cwd: invocation.spawnCwd,
      stdio: options.stdio || 'pipe'
    });

    let stdout = '';
    let stderr = '';

    if (child.stdout) {
      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });
    }

    if (child.stderr) {
      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });
    }

    child.on('close', (code) => {
      if (code === 0) {
        resolve({
          success: true,
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          code
        });
      } else {
        log(`Qwen-Code command failed with code ${code}: ${stderr}`, 'ERROR');
        reject(new Error(`Command failed with code ${code}: ${stderr || 'Unknown error'}`));
      }
    });

    child.on('error', (error) => {
      log(`Failed to start Qwen-Code process: ${error.message}`, 'ERROR');
      reject(new Error(`Failed to start process: ${error.message}`));
    });
  });
};

// 健康检查端点
app.get('/health', async (req, res) => {
  try {
    const { cliPath, triedPaths, source } = resolveQwenCliPath();

    if (!cliPath) {
      return res.status(503).json({
        status: 'unhealthy',
        message: 'Qwen-Code CLI not found',
        tried_paths: triedPaths,
        hint: 'Build qwen-code first (packages/cli/dist) or set QWEN_CLI_PATH to a valid CLI entry file.'
      });
    }

    // 尝试执行简单命令测试
    try {
      const version = await executeQwenCommand('--version', [], { stdio: 'pipe' });
      res.json({
        status: 'healthy',
        message: 'Qwen-Code service is running',
        port: PORT,
        qwen_cli_path: cliPath,
        qwen_cli_source: source,
        qwen_cli_version_stdout: version.stdout
      });
    } catch (error) {
      res.status(503).json({
        status: 'unhealthy',
        message: 'Qwen-Code CLI test failed',
        error: error.message,
        qwen_cli_path: cliPath
      });
    }
  } catch (error) {
    log(`Health check failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

app.post('/init', async (req, res) => {
  try {
    const {
      target_dir,
      project_name,
      description,
      overwrite = false
    } = req.body || {};

    if (!target_dir || typeof target_dir !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'target_dir is required'
      });
    }

    const absoluteTargetDir = path.isAbsolute(target_dir)
      ? target_dir
      : path.resolve(getDefaultWorkingDir(), target_dir);
    const qwenMdPath = path.join(absoluteTargetDir, 'QWEN.md');

    await fs.ensureDir(absoluteTargetDir);

    const exists = await fs.pathExists(qwenMdPath);
    if (exists && !overwrite) {
      return res.status(409).json({
        success: false,
        error: 'QWEN.md already exists. Set overwrite=true to replace it.',
        file_path: qwenMdPath
      });
    }

    const contentLines = [
      '# QWEN.md',
      '',
      project_name ? `## Project\n\n${project_name}` : '## Project',
      '',
      description ? `## Description\n\n${description}` : '## Description',
      '',
      '## Notes',
      '',
      '- This file is generated by Web Analyzer V2 init endpoint.',
      '- Describe your project goals, constraints, and important context here.',
      ''
    ];

    await fs.writeFile(qwenMdPath, contentLines.join('\n'), 'utf8');

    return res.json({
      success: true,
      target_dir: absoluteTargetDir,
      file_path: qwenMdPath,
      overwritten: !!exists,
      message: 'QWEN.md generated successfully'
    });
  } catch (error) {
    log(`Init failed: ${error.message}`, 'ERROR');
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 代码分析端点
app.post('/analyze-code', async (req, res) => {
  const requestId = req.body.request_id || uuidv4();
  
  try {
    const { code, analysis_type = 'full', options = {} } = req.body;
    
    if (!code || typeof code !== 'string') {
      return res.status(400).json({
        error: 'Code content is required and must be a string'
      });
    }

    log(`Starting code analysis: ${requestId}`, 'INFO');
    
    // 创建临时文件存储代码
    const tempDir = path.resolve(__dirname, 'temp');
    await fs.ensureDir(tempDir);
    
    const tempFile = path.join(tempDir, `analysis_${requestId}.js`);
    await fs.writeFile(tempFile, code, 'utf8');

    // 构建分析参数
    const args = [tempFile];
    
    if (analysis_type === 'functions') {
      args.push('--functions');
    } else if (analysis_type === 'security') {
      args.push('--security');
    } else if (analysis_type === 'structure') {
      args.push('--structure');
    }

    if (options.format === 'json') {
      args.push('--format', 'json');
    }

    if (options.no_interactive !== false) {
      args.push('--no-interactive');
    }

    // 执行分析
    const result = await executeQwenCommand('analyze', args);
    
    // 清理临时文件
    await fs.remove(tempFile).catch(() => {});
    
    // 解析结果
    let analysisResult;
    try {
      analysisResult = JSON.parse(result.stdout);
    } catch (parseError) {
      // 如果不是JSON格式，返回原始文本
      analysisResult = {
        analysis: result.stdout,
        raw_output: true
      };
    }

    // 存储结果
    analysisResults.set(requestId, {
      ...analysisResult,
      request_id: requestId,
      timestamp: new Date().toISOString(),
      analysis_type,
      options
    });

    log(`Code analysis completed: ${requestId}`, 'INFO');
    
    res.json({
      success: true,
      request_id: requestId,
      ...analysisResult
    });

  } catch (error) {
    log(`Code analysis failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      success: false,
      error: error.message,
      request_id: requestId
    });
  }
});

// 目录分析端点
app.post('/analyze-directory', async (req, res) => {
  const requestId = uuidv4();
  
  try {
    const { 
      directory_path, 
      include_patterns = ['*.js', '*.ts', '*.jsx', '*.tsx'],
      exclude_patterns = ['node_modules', 'dist', 'build']
    } = req.body;
    
    if (!directory_path) {
      return res.status(400).json({
        error: 'Directory path is required'
      });
    }

    log(`Starting directory analysis: ${requestId} - ${directory_path}`, 'INFO');
    
    // 构建参数
    const args = [directory_path];
    
    include_patterns.forEach(pattern => {
      args.push('--include', pattern);
    });
    
    exclude_patterns.forEach(pattern => {
      args.push('--exclude', pattern);
    });

    args.push('--format', 'json', '--no-interactive');

    // 执行分析
    const result = await executeQwenCommand('analyze', args);
    
    let analysisResult;
    try {
      analysisResult = JSON.parse(result.stdout);
    } catch (parseError) {
      analysisResult = {
        analysis: result.stdout,
        raw_output: true
      };
    }

    log(`Directory analysis completed: ${requestId}`, 'INFO');
    
    res.json({
      success: true,
      request_id: requestId,
      directory: directory_path,
      ...analysisResult
    });

  } catch (error) {
    log(`Directory analysis failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      success: false,
      error: error.message,
      request_id: requestId
    });
  }
});

// 聊天端点
app.post('/chat', async (req, res) => {
  const requestId = req.body.request_id || uuidv4();
  
  try {
    const { message, context = {}, save_session = false, session_tag } = req.body;
    
    if (!message) {
      return res.status(400).json({
        error: 'Message is required'
      });
    }

    log(`Starting chat: ${requestId}`, 'INFO');
    
    // 检查是否有可用的 CLI
    const invocation = buildQwenInvocation('chat', ['--version']);
    if (invocation.error) {
      log(`CLI not available, using mock mode: ${invocation.error.message}`, 'WARN');
      
      // Mock 聊天响应
      const mockResponse = {
        success: true,
        request_id: requestId,
        message: message,
        response: `这是一个模拟的 Qwen 回复。您的问题是：${message}\n\n由于 Qwen-Code CLI 未正确安装，当前运行在模拟模式下。要使用真实的 AI 功能，请：\n1. 确保 Qwen-Code CLI 已正确安装和构建\n2. 检查 QWEN_REPO_ROOT 环境变量指向正确的路径\n3. 运行 'npm run build' 构建 CLI\n\n当前模拟回复时间：${new Date().toLocaleString()}`,
        session_tag: session_tag || `mock-session-${Date.now()}`,
        context: context,
        timestamp: new Date().toISOString()
      };
      
      return res.json(mockResponse);
    }
    
    // 构建聊天参数
    const args = [];
    
    if (save_session && session_tag) {
      args.push('--save', session_tag);
    }
    
    args.push('--format', 'json', '--no-interactive');
    args.push(message);

    // 执行聊天
    const result = await executeQwenCommand('chat', args);
    
    let chatResult;
    try {
      chatResult = JSON.parse(result.stdout);
    } catch (parseError) {
      chatResult = {
        response: result.stdout,
        raw_output: true
      };
    }

    log(`Chat completed: ${requestId}`, 'INFO');
    
    res.json({
      success: true,
      request_id: requestId,
      ...chatResult
    });

  } catch (error) {
    log(`Chat failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      success: false,
      error: error.message,
      request_id: requestId
    });
  }
});

// 会话管理端点
app.get('/chat/list', async (req, res) => {
  try {
    const result = await executeQwenCommand('chat', ['--list', '--format', 'json']);
    
    let sessions;
    try {
      sessions = JSON.parse(result.stdout);
    } catch (parseError) {
      sessions = { sessions: [] };
    }

    res.json(sessions);
  } catch (error) {
    log(`List sessions failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      error: error.message
    });
  }
});

app.post('/chat/save', async (req, res) => {
  try {
    const { session_tag } = req.body;
    
    if (!session_tag) {
      return res.status(400).json({
        error: 'Session tag is required'
      });
    }

    await executeQwenCommand('chat', ['--save', session_tag]);
    
    res.json({
      success: true,
      session_tag,
      message: 'Session saved successfully'
    });
  } catch (error) {
    log(`Save session failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      error: error.message
    });
  }
});

app.post('/chat/resume/:session_tag', async (req, res) => {
  try {
    const { session_tag } = req.params;
    
    const result = await executeQwenCommand('chat', ['--resume', session_tag, '--format', 'json']);
    
    let sessionData;
    try {
      sessionData = JSON.parse(result.stdout);
    } catch (parseError) {
      sessionData = { context: result.stdout };
    }

    res.json({
      success: true,
      session_tag,
      ...sessionData
    });
  } catch (error) {
    log(`Resume session failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      error: error.message
    });
  }
});

app.delete('/chat/:session_tag', async (req, res) => {
  try {
    const { session_tag } = req.params;
    
    await executeQwenCommand('chat', ['--delete', session_tag]);
    
    res.json({
      success: true,
      session_tag,
      message: 'Session deleted successfully'
    });
  } catch (error) {
    log(`Delete session failed: ${error.message}`, 'ERROR');
    res.status(500).json({
      error: error.message
    });
  }
});

// 流式分析端点
app.post('/stream-analyze', (req, res) => {
  const requestId = uuidv4();
  
  try {
    const { code, query } = req.body;
    
    if (!code) {
      return res.status(400).json({
        error: 'Code is required for streaming analysis'
      });
    }

    // 设置SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    log(`Starting streaming analysis: ${requestId}`, 'INFO');
    
    // 创建临时文件
    const tempDir = path.resolve(__dirname, 'temp');
    fs.ensureDirSync(tempDir);
    
    const tempFile = path.join(tempDir, `stream_analysis_${requestId}.js`);
    fs.writeFileSync(tempFile, code, 'utf8');

    const invocation = buildQwenInvocation('analyze', [tempFile, '--stream', '--format', 'json'], {
      cwd: getDefaultWorkingDir()
    });
    if (invocation.error) {
      throw invocation.error;
    }

    const child = spawn('node', invocation.fullArgs, {
      env: invocation.env,
      cwd: invocation.spawnCwd
    });

    child.stdout.on('data', (data) => {
      const chunk = data.toString();
      res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk, request_id: requestId })}\n\n`);
    });

    child.stderr.on('data', (data) => {
      const error = data.toString();
      res.write(`data: ${JSON.stringify({ type: 'error', error, request_id: requestId })}\n\n`);
    });

    child.on('close', (code) => {
      fs.removeSync(tempFile);
      
      if (code === 0) {
        res.write(`data: ${JSON.stringify({ type: 'complete', request_id: requestId })}\n\n`);
      } else {
        res.write(`data: ${JSON.stringify({ type: 'error', error: `Process exited with code ${code}`, request_id: requestId })}\n\n`);
      }
      
      res.end();
      log(`Streaming analysis completed: ${requestId}`, 'INFO');
    });

    // 处理客户端断开连接
    req.on('close', () => {
      child.kill();
      fs.removeSync(tempFile);
      log(`Client disconnected, stopping analysis: ${requestId}`, 'INFO');
    });

  } catch (error) {
    log(`Streaming analysis failed: ${error.message}`, 'ERROR');
    res.write(`data: ${JSON.stringify({ type: 'error', error: error.message, request_id: requestId })}\n\n`);
    res.end();
  }
});

// 配置管理端点
app.get('/config', (req, res) => {
  const { cliPath, triedPaths, source } = resolveQwenCliPath();
  res.json({
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    api_key_configured: !!process.env.OPENAI_API_KEY,
    base_url: process.env.OPENAI_BASE_URL,
    model: process.env.OPENAI_MODEL,
    qwen_cli_path: cliPath,
    qwen_cli_source: source,
    qwen_cli_tried_paths: triedPaths
  });
});

app.post('/config', (req, res) => {
  // 这个端点可以用于运行时更新配置
  const { api_key, base_url, model } = req.body;
  
  if (api_key) process.env.OPENAI_API_KEY = api_key;
  if (base_url) process.env.OPENAI_BASE_URL = base_url;
  if (model) process.env.OPENAI_MODEL = model;
  
  log('Configuration updated', 'INFO');
  
  res.json({
    success: true,
    message: 'Configuration updated successfully',
    config: {
      api_key_configured: !!process.env.OPENAI_API_KEY,
      base_url: process.env.OPENAI_BASE_URL,
      model: process.env.OPENAI_MODEL
    }
  });
});

// 错误处理中间件
app.use((err, req, res, next) => {
  log(`Unhandled error: ${err.message}`, 'ERROR');
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// 404 处理
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// 启动服务器
app.listen(PORT, () => {
  log(`Qwen-Code HTTP wrapper listening on port ${PORT}`, 'INFO');
  log(`Health check available at: http://localhost:${PORT}/health`, 'INFO');
  
  // 确保临时目录存在
  const tempDir = path.resolve(__dirname, 'temp');
  fs.ensureDirSync(tempDir);
  
  // 启动时清理旧的临时文件
  fs.emptyDirSync(tempDir);
});

// 优雅关闭
process.on('SIGTERM', () => {
  log('Received SIGTERM, shutting down gracefully', 'INFO');
  process.exit(0);
});

process.on('SIGINT', () => {
  log('Received SIGINT, shutting down gracefully', 'INFO');
  process.exit(0);
});

module.exports = app;
