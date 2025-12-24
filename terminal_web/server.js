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

// Handle socket connections
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

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
    console.log(`Terminal exited with code: ${exitCode}, signal: ${signal}`);
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
    // Change to qwen-code directory first
    const qwenCodePath = path.resolve('../');
    ptyProcess.write(`cd "${qwenCodePath}"\r`);
    
    // Wait a moment then run qwen command
    setTimeout(() => {
      const qwenCommand = args ? `qwen ${args}\r` : 'qwen\r';
      ptyProcess.write(qwenCommand);
    }, 500);
  });

  // Clean up when client disconnects
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    ptyProcess.kill();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Qwen Code Web Terminal running on http://localhost:${PORT}`);
});
