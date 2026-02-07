const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const pty = require('node-pty');
const path = require('path');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

function getLocalIPv4() {
  const interfaces = os.networkInterfaces();
  for (const interfaceName of Object.keys(interfaces)) {
    const interfaceAddresses = interfaces[interfaceName] || [];
    for (const address of interfaceAddresses) {
      if (address && address.family === 'IPv4' && !address.internal) {
        return address.address;
      }
    }
  }
  return '127.0.0.1';
}

// Add CORS headers for all requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('X-Frame-Options', 'ALLOWALL');
  next();
});

// Serve static files
app.use(express.static('public'));

// Main route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'web-analyzer-terminal' });
});

// Handle socket connections
io.on('connection', (socket) => {
  console.log('[INFO] Terminal client connected:', socket.id);

  // Determine the shell based on platform - use cmd on Windows to avoid ExecutionPolicy issues
  const shell = os.platform() === 'win32' ? 'cmd.exe' : 'bash';
  const shellArgs = os.platform() === 'win32' ? [] : [];

  // Create a new pty process for this socket connection
  const ptyEnv = { ...process.env };
  const keepDebugEnv = String(process.env.TERMINAL_KEEP_DEBUG || '').toLowerCase() === 'true';
  if (!keepDebugEnv) {
    delete ptyEnv.DEBUG;
    delete ptyEnv.NODE_DEBUG;
    delete ptyEnv.PYTHONDEBUG;
    delete ptyEnv.PYTHONVERBOSE;
  }

  const ptyProcess = pty.spawn(shell, shellArgs, {
    name: 'xterm-color',
    cols: 80,
    rows: 24,
    cwd: process.cwd(),
    env: ptyEnv
  });

  // Send terminal data to client
  ptyProcess.onData((data) => {
    socket.emit('output', data);
  });

  // Handle terminal exit
  ptyProcess.onExit(({ exitCode, signal }) => {
    console.log(`[INFO] Terminal session ended: ${socket.id} (code: ${exitCode})`);
    socket.emit('exit', { exitCode, signal });
  });

  // Handle input from client
  socket.on('input', (data) => {
    ptyProcess.write(data);
  });

  // Handle terminal resize
  socket.on('resize', (size) => {
    ptyProcess.resize(size.cols, size.rows);
  });

  // Handle AI command execution (支持多个AI模型)
  socket.on('run-ai', (data = {}) => {
    const { model = 'qwen', args = '' } = data;
    const aiCommand = args ? `${model} ${args}\r` : `${model}\r`;
    console.log(`[INFO] Running AI command: ${aiCommand.trim()}`);
    ptyProcess.write(aiCommand);
  });

  // Handle qwen command execution (保持兼容性)
  socket.on('run-qwen', (args = '') => {
    // Change to specified directory first if provided
    const qwenCommand = args ? `qwen ${args}\r` : 'qwen\r';
    ptyProcess.write(qwenCommand);
  });

  // Handle session switching (支持多AI模型)
  socket.on('switch-session', (data) => {
    // 兼容旧格式：如果传入字符串，视为sessionPath
    const sessionPath = typeof data === 'string' ? data : data.path;
    const aiModel = typeof data === 'object' ? data.aiModel || 'qwen' : 'qwen';
    const aiCommand = typeof data === 'object' ? data.aiCommand || 'qwen' : 'qwen';
    
    console.log('[INFO] Switching to session:', sessionPath);
    console.log('[INFO] Using AI model:', aiModel, 'with command:', aiCommand);
    
    // Send Ctrl+C to cancel any running process
    ptyProcess.write('\x03');
    setTimeout(() => {
      ptyProcess.write('\x03');
    }, 120);
    
    // Wait then change directory
    setTimeout(() => {
      ptyProcess.write(`cd "${sessionPath}"\r`);
      
      // Wait then clear screen & run selected AI model
      setTimeout(() => {
        const clearCmd = os.platform() === 'win32' ? 'cls' : 'clear';
        ptyProcess.write(`${clearCmd}\r`);
        setTimeout(() => {
          ptyProcess.write(`${aiCommand}\r`);
          console.log(`[INFO] ${aiModel} started in session:`, sessionPath);
        }, 120);
      }, 350);
    }, 600);
  });

  // Clean up when client disconnects
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    ptyProcess.kill();
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  const localIp = getLocalIPv4();
  console.log(`Web Analyzer Terminal Service running on port ${PORT}`);
  console.log(`[INFO] Terminal(localhost): http://localhost:${PORT}`);
  console.log(`[INFO] Terminal(127.0.0.1): http://127.0.0.1:${PORT}`);
  console.log(`[INFO] Terminal(LAN): http://${localIp}:${PORT}`);
});
