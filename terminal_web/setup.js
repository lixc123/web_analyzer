const https = require('https');
const fs = require('fs');
const path = require('path');

// Create public/xterm directory
const xtermDir = path.join(__dirname, 'public', 'xterm');
if (!fs.existsSync(xtermDir)) {
  fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });
  fs.mkdirSync(xtermDir, { recursive: true });
}

// URLs for xterm.js files
const files = [
  {
    url: 'https://unpkg.com/xterm@5.3.0/lib/xterm.js',
    path: path.join(xtermDir, 'xterm.js')
  },
  {
    url: 'https://unpkg.com/xterm@5.3.0/css/xterm.css',
    path: path.join(xtermDir, 'xterm.css')
  },
  {
    url: 'https://unpkg.com/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js',
    path: path.join(xtermDir, 'xterm-addon-fit.js')
  },
  {
    url: 'https://unpkg.com/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.js',
    path: path.join(xtermDir, 'xterm-addon-web-links.js')
  }
];

// Download function
function downloadFile(url, filePath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(filePath);
    
    https.get(url, (response) => {
      if (response.statusCode === 200) {
        response.pipe(file);
        file.on('finish', () => {
          file.close();
          console.log(`Downloaded: ${path.basename(filePath)}`);
          resolve();
        });
      } else {
        reject(new Error(`Failed to download ${url}: ${response.statusCode}`));
      }
    }).on('error', (err) => {
      reject(err);
    });
  });
}

// Download all files
async function setupFiles() {
  console.log('Setting up xterm.js files...');
  
  try {
    for (const file of files) {
      if (!fs.existsSync(file.path)) {
        await downloadFile(file.url, file.path);
      } else {
        console.log(`Already exists: ${path.basename(file.path)}`);
      }
    }
    console.log('Setup complete!');
  } catch (error) {
    console.error('Setup failed:', error.message);
  }
}

setupFiles();
