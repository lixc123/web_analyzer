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

term.attachCustomKeyEventHandler((e) => {
  if (e.type !== 'keydown') return true;

  const isMac = navigator.platform.toLowerCase().includes('mac');
  const mod = isMac ? e.metaKey : e.ctrlKey;
  if (!mod) return true;

  const isC = e.code === 'KeyC' || e.key === 'c' || e.key === 'C';
  const isV = e.code === 'KeyV' || e.key === 'v' || e.key === 'V';

  if (isC && term.hasSelection()) {
    const text = term.getSelection();
    if (text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {});
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          document.execCommand('copy');
        } catch {}
        document.body.removeChild(textarea);
      }
    }
    return false;
  }

  if (isV) {
    if (!(navigator.clipboard && navigator.clipboard.readText)) return true;
    navigator.clipboard.readText().then((text) => {
      if (text && socket.connected) socket.emit('input', text);
    }).catch(() => {});
    return false;
  }

  return true;
});

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
  console.log('Connected to server');
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
  console.log('Disconnected from server');
  term.write('\r\n\x1b[31mDisconnected from server\x1b[0m\r\n');
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

// Control functions
function startQwen() {
  socket.emit('run-qwen');
}

function clearTerminal() {
  term.clear();
}

// Listen for commands from parent window (iframe communication)
window.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'command') {
    const command = event.data.data;
    console.log('Received command from parent:', command);
    
    // Send command to terminal
    if (socket.connected) {
      socket.emit('input', command);
    }
  }
});

// Focus terminal
term.focus();
