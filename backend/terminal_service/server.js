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
  console.log('🔗 Terminal client connected:', socket.id);

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
    console.log(`🔚 Terminal session ended: ${socket.id} (code: ${exitCode})`);
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

  // Handle qwen command execution
  socket.on('run-qwen', (args = '') => {
    // Change to specified directory first if provided
    const qwenCommand = args ? `qwen ${args}\r` : 'qwen\r';
    ptyProcess.write(qwenCommand);
  });

  // Handle session switching
  socket.on('switch-session', (sessionPath) => {
    console.log('🔄 Switching to session:', sessionPath);
    
    // Send Ctrl+C to cancel any running process
    ptyProcess.write('\x03');
    setTimeout(() => {
      ptyProcess.write('\x03');
    }, 120);
    
    // Wait then change directory
    setTimeout(() => {
      ptyProcess.write(`cd "${sessionPath}"\r`);
      
      // Wait then clear screen & run qwen
      setTimeout(() => {
        const clearCmd = os.platform() === 'win32' ? 'cls' : 'clear';
        ptyProcess.write(`${clearCmd}\r`);
        setTimeout(() => {
          ptyProcess.write('qwen\r');
          console.log('🚀 Qwen started in session:', sessionPath);
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
server.listen(PORT, () => {
  console.log(`Web Analyzer Terminal Service running on http://localhost:${PORT}`);
});
