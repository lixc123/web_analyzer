// Initialize socket connection
const socket = io();

// Initialize xterm.js terminal
const term = new Terminal({
  cursorBlink: true,
  theme: {
    background: '#1a1a1a',
    foreground: '#ffffff',
    cursor: '#ffffff',
    selection: '#4a9eff'
  },
  fontFamily: 'Consolas, Monaco, "Courier New", monospace',
  fontSize: 14,
  lineHeight: 1.2
});

// Add-ons
const fitAddon = new FitAddon.FitAddon();
const webLinksAddon = new WebLinksAddon.WebLinksAddon();

term.loadAddon(fitAddon);
term.loadAddon(webLinksAddon);

// Open terminal in the DOM
term.open(document.getElementById('terminal'));

// Fit terminal to container
function resizeTerminal() {
  fitAddon.fit();
  socket.emit('resize', {
    cols: term.cols,
    rows: term.rows
  });
}

// Socket event handlers
socket.on('connect', () => {
  console.log('Connected to terminal service');
  document.getElementById('loading').style.display = 'none';
  
  // Fit terminal after connection
  setTimeout(() => {
    resizeTerminal();
  }, 100);
});

socket.on('output', (data) => {
  term.write(data);
});

socket.on('disconnect', () => {
  console.log('Disconnected from terminal service');
  term.write('\r\n\x1b[31mDisconnected from terminal service\x1b[0m\r\n');
});

socket.on('exit', (data) => {
  term.write(`\r\n\x1b[33mTerminal exited with code: ${data.exitCode}\x1b[0m\r\n`);
});

// Terminal input handling
term.onData((data) => {
  socket.emit('input', data);
});

// Window resize handling
window.addEventListener('resize', () => {
  setTimeout(resizeTerminal, 100);
});

// Listen for commands from parent window (iframe communication)
window.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'command') {
    const command = event.data.data;
    console.log('Received command from parent:', command);
    
    // Send command to terminal
    if (socket.connected) {
      socket.emit('input', command);
    }
  } else if (event.data && event.data.type === 'switch-session') {
    const sessionPath = event.data.path;
    console.log('Switching to session:', sessionPath);
    
    // Use the switch-session event for better handling
    if (socket.connected) {
      socket.emit('switch-session', sessionPath);
    }
  }
});

// Focus terminal
term.focus();
