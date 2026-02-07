/**
 * Windows API Hook（可配置模块化）
 *
 * 说明：
 * - 本脚本用于“监控/定位”网络与加密调用，辅助解决：
 *   - 应用不走系统代理（WinHTTP/WinINet/Winsock 直连）
 *   - 需要定位请求构造点/加密点（签名、参数组装）
 *
 * - 该脚本不保证对所有应用无副作用：请按需启用模块，避免噪音与性能影响。
 *
 * 模板参数（由后端 Template.render 替换）：
 * - enable_winhttp / enable_wininet / enable_winsock / enable_crypto
 * - enable_file / enable_registry
 * - max_preview（文本/hex 预览长度）
 * - hexdump（true 时对二进制使用 hex 预览）
 * - sample_rate（0~1，采样比例；默认 1）
 * - capture_stack_trace（true 时附带调用栈；默认 false，开销较大）
 * - max_stack_depth（栈深度上限）
 * - dump_raw_buffers（true 时通过 Frida data 通道发送原始 buffer，供后端可选落盘）
 * - raw_max_bytes（单条事件 raw 发送上限）
 * - raw_total_budget_bytes（单会话 raw 总预算上限，超过后自动停发）
 * - winsock_reassemble（true 时按 socket 聚合 send/recv 预览，默认关闭）
 * - winsock_reassemble_max_bytes（winsock 聚合缓冲上限）
 */

(function () {
  'use strict';

  const CONFIG = {
    enable_winhttp: {{enable_winhttp}},
    enable_wininet: {{enable_wininet}},
    enable_winsock: {{enable_winsock}},
    enable_crypto: {{enable_crypto}},
    enable_file: {{enable_file}},
    enable_registry: {{enable_registry}},
    max_preview: {{max_preview}},
    hexdump: {{hexdump}},
    sample_rate: {{sample_rate}},
    capture_stack_trace: {{capture_stack_trace}},
    max_stack_depth: {{max_stack_depth}},
    dump_raw_buffers: {{dump_raw_buffers}},
    raw_max_bytes: {{raw_max_bytes}},
    raw_total_budget_bytes: {{raw_total_budget_bytes}},
    winsock_reassemble: {{winsock_reassemble}},
    winsock_reassemble_max_bytes: {{winsock_reassemble_max_bytes}},
  };

  const WINHTTP_FLAG_SECURE = 0x00800000;
  const INTERNET_FLAG_SECURE = 0x00800000;

  function now() {
    return Date.now();
  }

  function safeToInt(v) {
    try {
      return v.toInt32();
    } catch (_) {
      return 0;
    }
  }

  function safeReadUtf16(ptr, lengthChars) {
    try {
      if (!ptr || ptr.isNull()) return '';
      const n = typeof lengthChars === 'number' ? lengthChars : 0;
      if (n > 0 && n < 0x20000) {
        return ptr.readUtf16String(n);
      }
      return ptr.readUtf16String();
    } catch (_) {
      return '';
    }
  }

  function safeReadUtf8(ptr, lengthBytes) {
    try {
      if (!ptr || ptr.isNull()) return '';
      const n = typeof lengthBytes === 'number' ? lengthBytes : 0;
      if (n > 0 && n < 0x200000) {
        return ptr.readUtf8String(n);
      }
      return ptr.readUtf8String();
    } catch (_) {
      return '';
    }
  }

  function bytesToHex(bytes, limit) {
    try {
      const max = Math.max(0, Math.min(bytes.length, limit));
      let out = '';
      for (let i = 0; i < max; i++) {
        const b = bytes[i] & 0xff;
        out += (b < 16 ? '0' : '') + b.toString(16);
      }
      if (bytes.length > max) out += '...[truncated]';
      return out;
    } catch (_) {
      return '';
    }
  }

  function previewBytes(ptr, len, isTextHint) {
    const max = Math.max(0, Math.min(len, CONFIG.max_preview || 4096));
    if (!ptr || ptr.isNull() || max <= 0) return '';
    try {
      const buf = ptr.readByteArray(max);
      const bytes = new Uint8Array(buf);

      if (isTextHint) {
        // best-effort utf8
        try {
          const text = safeReadUtf8(ptr, max);
          if (text) return text.length > max ? text.slice(0, max) + '...[truncated]' : text;
        } catch (_) {}
      }
      if (CONFIG.hexdump) {
        return bytesToHex(bytes, CONFIG.max_preview || 4096);
      }
      return `<binary ${len} bytes>`;
    } catch (_) {
      return '';
    }
  }

  function maybeAddStack(payload, context) {
    if (!CONFIG.capture_stack_trace) return;
    if (!context) return;
    try {
      payload.thread_id = Process.getCurrentThreadId();
    } catch (_) {}
    try {
      const depth = Math.max(1, Math.min(CONFIG.max_stack_depth || 16, 64));
      const bt = Thread.backtrace(context, Backtracer.FUZZY)
        .slice(0, depth)
        .map(DebugSymbol.fromAddress)
        .join('\n');
      payload.stack_trace = bt;
    } catch (_) {}
  }

  let __rawBudgetUsed = 0;

  function sendEvent(payload, context, rawPtr, rawLen) {
    try {
      const sr = typeof CONFIG.sample_rate === 'number' ? CONFIG.sample_rate : 1;
      if (sr > 0 && sr < 1) {
        if (Math.random() > sr) return;
      }
      maybeAddStack(payload, context);
      payload.timestamp = now();

      // 可选：发送原始 buffer（供后端落盘/AI 对比）。受总预算与单条上限控制。
      if (CONFIG.dump_raw_buffers && rawPtr && typeof rawLen === 'number' && rawLen > 0) {
        try {
          if (rawPtr.isNull && rawPtr.isNull()) {
            send(payload);
            return;
          }
        } catch (_) {}
        const totalBudget = typeof CONFIG.raw_total_budget_bytes === 'number' ? CONFIG.raw_total_budget_bytes : 0;
        if (totalBudget <= 0) {
          payload.raw_skipped = true;
          payload.raw_reason = 'budget_not_set';
          send(payload);
          return;
        }

        const maxPer = typeof CONFIG.raw_max_bytes === 'number' && CONFIG.raw_max_bytes > 0 ? CONFIG.raw_max_bytes : 4096;
        const remaining = Math.max(0, totalBudget - __rawBudgetUsed);
        const cap = Math.max(0, Math.min(rawLen, maxPer, remaining));

        if (remaining <= 0) {
          payload.raw_skipped = true;
          payload.raw_reason = 'budget_exhausted';
          send(payload);
          return;
        }

        if (cap > 0) {
          try {
            const buf = rawPtr.readByteArray(cap);
            payload.raw_total_len = rawLen;
            payload.raw_sent_len = cap;
            payload.raw_truncated = cap < rawLen;
            __rawBudgetUsed += cap;
            send(payload, buf);
            return;
          } catch (_) {
            payload.raw_skipped = true;
            payload.raw_reason = 'read_failed';
          }
        } else {
          payload.raw_skipped = true;
          payload.raw_reason = 'cap_zero';
        }
      }

      send(payload);
    } catch (_) {}
  }

  // ------------- WinHTTP -------------
  const winhttpConnectMap = {}; // hConnect -> {host, port}
  const winhttpRequestMap = {}; // hRequest -> {method, path, flags, connect, extraHeaders}

  function winhttpPeer(req) {
    try {
      if (!req) return null;
      const conn = winhttpConnectMap[req.connect] || null;
      if (!conn) return null;
      return { host: conn.host || '', port: conn.port || 0 };
    } catch (_) {
      return null;
    }
  }

  function buildWinhttpUrl(req) {
    try {
      if (!req) return '';
      const conn = winhttpConnectMap[req.connect] || {};
      const host = conn.host || '';
      const port = conn.port || 0;
      const isSecure = (req.flags & WINHTTP_FLAG_SECURE) !== 0;
      const scheme = isSecure ? 'https' : 'http';
      const path = req.path || '/';
      const portPart =
        port && ((scheme === 'https' && port !== 443) || (scheme === 'http' && port !== 80)) ? `:${port}` : '';
      if (!host) return path;
      return `${scheme}://${host}${portPart}${path.startsWith('/') ? '' : '/'}${path}`;
    } catch (_) {
      return '';
    }
  }

  function hookWinHttp() {
    try {
      const moduleName = 'winhttp.dll';

      const WinHttpConnect = Module.findExportByName(moduleName, 'WinHttpConnect');
      if (WinHttpConnect) {
        Interceptor.attach(WinHttpConnect, {
          onEnter(args) {
            this.serverName = safeReadUtf16(args[1]);
            this.serverPort = safeToInt(args[2]);
          },
          onLeave(retval) {
            const hConnect = retval;
            const key = hConnect.toString();
            winhttpConnectMap[key] = { host: this.serverName || '', port: this.serverPort || 0 };
            sendEvent({
              type: 'network',
              api: 'WinHttpConnect',
              handle: key,
              host: this.serverName || '',
              port: this.serverPort || 0,
            }, this.context);
          },
        });
      }

      const WinHttpOpenRequest = Module.findExportByName(moduleName, 'WinHttpOpenRequest');
      if (WinHttpOpenRequest) {
        Interceptor.attach(WinHttpOpenRequest, {
          onEnter(args) {
            this.hConnect = args[0].toString();
            this.verb = safeReadUtf16(args[1]);
            this.objectName = safeReadUtf16(args[2]);
            this.flags = safeToInt(args[6]);
          },
          onLeave(retval) {
            const hRequest = retval;
            const key = hRequest.toString();
            winhttpRequestMap[key] = {
              method: this.verb || 'GET',
              path: this.objectName || '/',
              flags: this.flags || 0,
              connect: this.hConnect,
              extraHeaders: '',
            };
            sendEvent({
              type: 'network',
              api: 'WinHttpOpenRequest',
              handle: key,
              method: this.verb || 'GET',
              path: this.objectName || '/',
              flags: this.flags || 0,
              url: buildWinhttpUrl(winhttpRequestMap[key]),
              peer: winhttpPeer(winhttpRequestMap[key]),
            }, this.context);
          },
        });
      }

      const WinHttpAddRequestHeaders = Module.findExportByName(moduleName, 'WinHttpAddRequestHeaders');
      if (WinHttpAddRequestHeaders) {
        Interceptor.attach(WinHttpAddRequestHeaders, {
          onEnter(args) {
            const hRequest = args[0].toString();
            const hdrLen = safeToInt(args[2]);
            const headers = safeReadUtf16(args[1], hdrLen > 0 ? hdrLen : undefined);
            const req = winhttpRequestMap[hRequest];
            if (req) {
              req.extraHeaders = (req.extraHeaders || '') + (headers || '');
            }
            sendEvent({
              type: 'network',
              api: 'WinHttpAddRequestHeaders',
              handle: hRequest,
              headers: headers || '',
              url: req ? buildWinhttpUrl(req) : '',
              peer: req ? winhttpPeer(req) : null,
            }, this.context);
          },
        });
      }

      const WinHttpSendRequest = Module.findExportByName(moduleName, 'WinHttpSendRequest');
      if (WinHttpSendRequest) {
        Interceptor.attach(WinHttpSendRequest, {
          onEnter(args) {
            const hRequest = args[0].toString();
            const hdrLen = safeToInt(args[2]);
            const headers = safeReadUtf16(args[1], hdrLen > 0 ? hdrLen : undefined);
            const opt = args[3];
            const optLen = safeToInt(args[4]);

            const req = winhttpRequestMap[hRequest];
            const url = req ? buildWinhttpUrl(req) : '';
            const method = req ? req.method : '';
            const mergedHeaders = (req && req.extraHeaders ? req.extraHeaders + '\n' : '') + (headers || '');

            sendEvent({
              type: 'network',
              api: 'WinHttpSendRequest',
              handle: hRequest,
              method: method,
              url: url,
              headers: mergedHeaders,
              body: opt && optLen > 0 ? previewBytes(opt, optLen, true) : '',
              body_length: optLen > 0 ? optLen : 0,
              peer: req ? winhttpPeer(req) : null,
            }, this.context);
          },
        });
      }

      // 分块发送：WinHttpWriteData
      const WinHttpWriteData = Module.findExportByName(moduleName, 'WinHttpWriteData');
      if (WinHttpWriteData) {
        Interceptor.attach(WinHttpWriteData, {
          onEnter(args) {
            this.hRequest = args[0].toString();
            this.buf = args[1];
            this.toWrite = safeToInt(args[2]);
            this.pWritten = args[3];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bytesWritten = 0;
            try {
              if (this.pWritten && !this.pWritten.isNull()) bytesWritten = this.pWritten.readU32();
            } catch (_) {}
            if (bytesWritten <= 0) bytesWritten = this.toWrite;
            if (bytesWritten <= 0) return;
            const req = winhttpRequestMap[this.hRequest];
            sendEvent({
              type: 'network',
              api: 'WinHttpWriteData',
              handle: this.hRequest,
              url: req ? buildWinhttpUrl(req) : '',
              peer: req ? winhttpPeer(req) : null,
              bytes_written: bytesWritten,
              data: previewBytes(this.buf, bytesWritten, true),
              layer: 'request_body_chunk',
            }, this.context, this.buf, bytesWritten);
          },
        });
      }

      // 响应元信息：WinHttpQueryHeaders（status/headers）
      const WinHttpQueryHeaders = Module.findExportByName(moduleName, 'WinHttpQueryHeaders');
      if (WinHttpQueryHeaders) {
        Interceptor.attach(WinHttpQueryHeaders, {
          onEnter(args) {
            this.hRequest = args[0].toString();
            this.infoLevel = safeToInt(args[1]);
            this.name = safeReadUtf16(args[2]);
            this.buf = args[3];
            this.pBufLen = args[4];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bufLen = 0;
            try {
              if (this.pBufLen && !this.pBufLen.isNull()) bufLen = this.pBufLen.readU32();
            } catch (_) {}
            if (!this.buf || this.buf.isNull() || bufLen <= 0) return;
            let text = '';
            try {
              const chars = Math.max(0, Math.min(0x20000, Math.floor(bufLen / 2)));
              text = safeReadUtf16(this.buf, chars);
            } catch (_) {}
            const req = winhttpRequestMap[this.hRequest];
            sendEvent({
              type: 'network',
              api: 'WinHttpQueryHeaders',
              handle: this.hRequest,
              url: req ? buildWinhttpUrl(req) : '',
              peer: req ? winhttpPeer(req) : null,
              info_level: this.infoLevel,
              header_name: this.name || '',
              headers: text || '',
              layer: 'response_meta',
            }, this.context);
          },
        });
      }

      const WinHttpReceiveResponse = Module.findExportByName(moduleName, 'WinHttpReceiveResponse');
      if (WinHttpReceiveResponse) {
        Interceptor.attach(WinHttpReceiveResponse, {
          onEnter(args) {
            this.hRequest = args[0].toString();
          },
          onLeave(retval) {
            const req = winhttpRequestMap[this.hRequest];
            sendEvent({
              type: 'network',
              api: 'WinHttpReceiveResponse',
              handle: this.hRequest,
              success: safeToInt(retval) !== 0,
              url: req ? buildWinhttpUrl(req) : '',
              peer: req ? winhttpPeer(req) : null,
            }, this.context);
          },
        });
      }

      const WinHttpReadData = Module.findExportByName(moduleName, 'WinHttpReadData');
      if (WinHttpReadData) {
        Interceptor.attach(WinHttpReadData, {
          onEnter(args) {
            this.hRequest = args[0].toString();
            this.buf = args[1];
            this.toRead = safeToInt(args[2]);
            this.pRead = args[3];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bytesRead = 0;
            try {
              if (this.pRead && !this.pRead.isNull()) bytesRead = this.pRead.readU32();
            } catch (_) {}
            if (bytesRead <= 0) return;
            const req = winhttpRequestMap[this.hRequest];
            sendEvent({
              type: 'network',
              api: 'WinHttpReadData',
              handle: this.hRequest,
              url: req ? buildWinhttpUrl(req) : '',
              peer: req ? winhttpPeer(req) : null,
              bytes_read: bytesRead,
              data: previewBytes(this.buf, bytesRead, false),
            }, this.context);
          },
        });
      }

      sendEvent({ type: 'info', api: 'winhttp', message: 'WinHTTP hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'winhttp', message: String(e) });
    }
  }

  // ------------- WinINet -------------
  const wininetConnectMap = {}; // hConnect -> {host, port}
  const wininetRequestMap = {}; // hRequest -> {method, path, flags, connect, extraHeaders}

  function wininetPeer(req) {
    try {
      if (!req) return null;
      const conn = wininetConnectMap[req.connect] || null;
      if (!conn) return null;
      return { host: conn.host || '', port: conn.port || 0 };
    } catch (_) {
      return null;
    }
  }

  function buildWininetUrl(req) {
    try {
      if (!req) return '';
      const conn = wininetConnectMap[req.connect] || {};
      const host = conn.host || '';
      const port = conn.port || 0;
      const isSecure = (req.flags & INTERNET_FLAG_SECURE) !== 0;
      const scheme = isSecure ? 'https' : 'http';
      const path = req.path || '/';
      const portPart =
        port && ((scheme === 'https' && port !== 443) || (scheme === 'http' && port !== 80)) ? `:${port}` : '';
      if (!host) return path;
      return `${scheme}://${host}${portPart}${path.startsWith('/') ? '' : '/'}${path}`;
    } catch (_) {
      return '';
    }
  }

  function hookWinInet() {
    try {
      const moduleName = 'wininet.dll';

      const InternetOpenW = Module.findExportByName(moduleName, 'InternetOpenW');
      if (InternetOpenW) {
        Interceptor.attach(InternetOpenW, {
          onEnter(args) {
            const agent = safeReadUtf16(args[0]);
            sendEvent({
              type: 'network',
              api: 'InternetOpenW',
              user_agent: agent,
              access_type: safeToInt(args[1]),
            }, this.context);
          },
        });
      }

      const InternetConnectW = Module.findExportByName(moduleName, 'InternetConnectW');
      if (InternetConnectW) {
        Interceptor.attach(InternetConnectW, {
          onEnter(args) {
            this.serverName = safeReadUtf16(args[1]);
            this.serverPort = safeToInt(args[2]);
          },
          onLeave(retval) {
            const hConnect = retval.toString();
            wininetConnectMap[hConnect] = { host: this.serverName || '', port: this.serverPort || 0 };
            sendEvent({
              type: 'network',
              api: 'InternetConnectW',
              handle: hConnect,
              host: this.serverName || '',
              port: this.serverPort || 0,
            }, this.context);
          },
        });
      }

      const HttpOpenRequestW = Module.findExportByName(moduleName, 'HttpOpenRequestW');
      if (HttpOpenRequestW) {
        Interceptor.attach(HttpOpenRequestW, {
          onEnter(args) {
            this.hConnect = args[0].toString();
            this.verb = safeReadUtf16(args[1]);
            this.objectName = safeReadUtf16(args[2]);
            this.flags = safeToInt(args[6]);
          },
          onLeave(retval) {
            const hRequest = retval.toString();
            wininetRequestMap[hRequest] = {
              method: this.verb || 'GET',
              path: this.objectName || '/',
              flags: this.flags || 0,
              connect: this.hConnect,
              extraHeaders: '',
            };
            sendEvent({
              type: 'network',
              api: 'HttpOpenRequestW',
              handle: hRequest,
              method: this.verb || 'GET',
              path: this.objectName || '/',
              flags: this.flags || 0,
              url: buildWininetUrl(wininetRequestMap[hRequest]),
              peer: wininetPeer(wininetRequestMap[hRequest]),
            }, this.context);
          },
        });
      }

      const HttpAddRequestHeadersW = Module.findExportByName(moduleName, 'HttpAddRequestHeadersW');
      if (HttpAddRequestHeadersW) {
        Interceptor.attach(HttpAddRequestHeadersW, {
          onEnter(args) {
            const hRequest = args[0].toString();
            const hdrLen = safeToInt(args[2]);
            const headers = safeReadUtf16(args[1], hdrLen > 0 ? hdrLen : undefined);
            const req = wininetRequestMap[hRequest];
            if (req) req.extraHeaders = (req.extraHeaders || '') + (headers || '');
            sendEvent({
              type: 'network',
              api: 'HttpAddRequestHeadersW',
              handle: hRequest,
              headers: headers || '',
              url: req ? buildWininetUrl(req) : '',
              peer: req ? wininetPeer(req) : null,
            }, this.context);
          },
        });
      }

      const HttpSendRequestW = Module.findExportByName(moduleName, 'HttpSendRequestW');
      if (HttpSendRequestW) {
        Interceptor.attach(HttpSendRequestW, {
          onEnter(args) {
            const hRequest = args[0].toString();
            const hdrLen = safeToInt(args[2]);
            const opt = args[3];
            const optLen = safeToInt(args[4]);
            const headers = safeReadUtf16(args[1], hdrLen > 0 ? hdrLen : undefined);

            const req = wininetRequestMap[hRequest];
            const url = req ? buildWininetUrl(req) : '';
            const mergedHeaders = (req && req.extraHeaders ? req.extraHeaders + '\n' : '') + (headers || '');

            sendEvent({
              type: 'network',
              api: 'HttpSendRequestW',
              handle: hRequest,
              method: req ? req.method : '',
              url: url,
              peer: req ? wininetPeer(req) : null,
              headers: mergedHeaders,
              body: opt && optLen > 0 ? previewBytes(opt, optLen, true) : '',
              body_length: optLen > 0 ? optLen : 0,
            }, this.context);
          },
        });
      }

      // 分块发送：HttpSendRequestExW + InternetWriteFile
      const HttpSendRequestExW = Module.findExportByName(moduleName, 'HttpSendRequestExW');
      if (HttpSendRequestExW) {
        Interceptor.attach(HttpSendRequestExW, {
          onEnter(args) {
            const hRequest = args[0].toString();
            const req = wininetRequestMap[hRequest];
            sendEvent({
              type: 'network',
              api: 'HttpSendRequestExW',
              handle: hRequest,
              method: req ? req.method : '',
              url: req ? buildWininetUrl(req) : '',
              peer: req ? wininetPeer(req) : null,
              layer: 'request_body_stream_begin',
            }, this.context);
          },
        });
      }

      const InternetWriteFile = Module.findExportByName(moduleName, 'InternetWriteFile');
      if (InternetWriteFile) {
        Interceptor.attach(InternetWriteFile, {
          onEnter(args) {
            this.hFile = args[0].toString();
            this.buf = args[1];
            this.toWrite = safeToInt(args[2]);
            this.pWritten = args[3];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bytesWritten = 0;
            try {
              if (this.pWritten && !this.pWritten.isNull()) bytesWritten = this.pWritten.readU32();
            } catch (_) {}
            if (bytesWritten <= 0) bytesWritten = this.toWrite;
            if (bytesWritten <= 0) return;
            const req = wininetRequestMap[this.hFile];
            sendEvent({
              type: 'network',
              api: 'InternetWriteFile',
              handle: this.hFile,
              url: req ? buildWininetUrl(req) : '',
              peer: req ? wininetPeer(req) : null,
              bytes_written: bytesWritten,
              data: previewBytes(this.buf, bytesWritten, true),
              layer: 'request_body_chunk',
            }, this.context, this.buf, bytesWritten);
          },
        });
      }

      // 响应元信息：HttpQueryInfoW（status/headers）
      const HttpQueryInfoW = Module.findExportByName(moduleName, 'HttpQueryInfoW');
      if (HttpQueryInfoW) {
        Interceptor.attach(HttpQueryInfoW, {
          onEnter(args) {
            this.hRequest = args[0].toString();
            this.infoLevel = safeToInt(args[1]);
            this.buf = args[2];
            this.pBufLen = args[3];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bufLen = 0;
            try {
              if (this.pBufLen && !this.pBufLen.isNull()) bufLen = this.pBufLen.readU32();
            } catch (_) {}
            if (!this.buf || this.buf.isNull() || bufLen <= 0) return;
            let text = '';
            try {
              const chars = Math.max(0, Math.min(0x20000, Math.floor(bufLen / 2)));
              text = safeReadUtf16(this.buf, chars);
            } catch (_) {}
            const req = wininetRequestMap[this.hRequest];
            sendEvent({
              type: 'network',
              api: 'HttpQueryInfoW',
              handle: this.hRequest,
              url: req ? buildWininetUrl(req) : '',
              peer: req ? wininetPeer(req) : null,
              info_level: this.infoLevel,
              value: text || '',
              layer: 'response_meta',
            }, this.context);
          },
        });
      }

      const InternetReadFile = Module.findExportByName(moduleName, 'InternetReadFile');
      if (InternetReadFile) {
        Interceptor.attach(InternetReadFile, {
          onEnter(args) {
            this.hFile = args[0].toString();
            this.buf = args[1];
            this.pRead = args[3];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let bytesRead = 0;
            try {
              if (this.pRead && !this.pRead.isNull()) bytesRead = this.pRead.readU32();
            } catch (_) {}
            if (bytesRead <= 0) return;
            const req = wininetRequestMap[this.hFile];
            sendEvent({
              type: 'network',
              api: 'InternetReadFile',
              handle: this.hFile,
              url: req ? buildWininetUrl(req) : '',
              peer: req ? wininetPeer(req) : null,
              bytes_read: bytesRead,
              data: previewBytes(this.buf, bytesRead, false),
            }, this.context);
          },
        });
      }

      sendEvent({ type: 'info', api: 'wininet', message: 'WinINet hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'wininet', message: String(e) });
    }
  }

  // ------------- Winsock -------------
  const socketPeerMap = {}; // socket -> {host, port}
  const winsockAgg = {}; // key(socket:direction) -> aggregated preview string

  function parseSockaddr(ptr) {
    try {
      if (!ptr || ptr.isNull()) return null;
      const family = ptr.readU16();
      if (family === 2) {
        // AF_INET
        const port = ptr.add(2).readU16();
        const addr = ptr.add(4).readU32();
        const b1 = addr & 0xff;
        const b2 = (addr >> 8) & 0xff;
        const b3 = (addr >> 16) & 0xff;
        const b4 = (addr >> 24) & 0xff;
        const host = `${b1}.${b2}.${b3}.${b4}`;
        return { host: host, port: ((port & 0xff) << 8) | ((port >> 8) & 0xff) };
      }
      return { host: '', port: 0, family: family };
    } catch (_) {
      return null;
    }
  }

  function hookWinsock() {
    try {
      const moduleName = 'ws2_32.dll';

      const connectFn = Module.findExportByName(moduleName, 'connect');
      if (connectFn) {
        Interceptor.attach(connectFn, {
          onEnter(args) {
            this.socket = args[0].toInt32();
            const peer = parseSockaddr(args[1]);
            if (peer) {
              socketPeerMap[String(this.socket)] = peer;
              sendEvent({
                type: 'network',
                api: 'connect',
                socket: this.socket,
                peer: peer,
              }, this.context);
            }
          },
        });
      }

      function emitSocketData(api, socket, buf, len, direction) {
        const peer = socketPeerMap[String(socket)] || null;
        const payload = {
          type: 'network',
          api: api,
          socket: socket,
          direction: direction,
          peer: peer,
          length: len,
          layer: 'fallback_winsock',
          data: buf && len > 0 ? previewBytes(buf, len, true) : '',
        };

        // 可选：按 socket 聚合 send/recv 预览（默认关闭，避免噪音）
        if (CONFIG.winsock_reassemble && !CONFIG.dump_raw_buffers && payload.data) {
          const maxAgg = typeof CONFIG.winsock_reassemble_max_bytes === 'number' && CONFIG.winsock_reassemble_max_bytes > 0 ? CONFIG.winsock_reassemble_max_bytes : 16384;
          const k = String(socket) + ':' + String(direction);
          const cur = winsockAgg[k] || '';
          const next = (cur + payload.data).slice(-maxAgg);
          winsockAgg[k] = next;
          const flushAt = Math.max(1024, Math.min(maxAgg, CONFIG.max_preview || 4096));
          if (next.length >= flushAt) {
            sendEvent({
              type: 'network',
              api: 'winsock_reassembled',
              socket: socket,
              direction: direction,
              peer: peer,
              aggregated: true,
              aggregated_chars: next.length,
              data: next,
              layer: 'fallback_winsock',
            });
            winsockAgg[k] = '';
          }
          return;
        }

        // 兜底层：默认只做 preview；若 dump_raw_buffers 开启，则附带 raw buffer（受预算限制）
        if (buf && len > 0) {
          sendEvent(payload, null, buf, len);
        } else {
          sendEvent(payload);
        }
      }

      const sendFn = Module.findExportByName(moduleName, 'send');
      if (sendFn) {
        Interceptor.attach(sendFn, {
          onEnter(args) {
            const socket = args[0].toInt32();
            const buf = args[1];
            const len = safeToInt(args[2]);
            if (len > 0) emitSocketData('send', socket, buf, Math.min(len, CONFIG.max_preview), 'send');
          },
        });
      }

      const recvFn = Module.findExportByName(moduleName, 'recv');
      if (recvFn) {
        Interceptor.attach(recvFn, {
          onEnter(args) {
            this.socket = args[0].toInt32();
            this.buf = args[1];
          },
          onLeave(retval) {
            const n = safeToInt(retval);
            if (n > 0) emitSocketData('recv', this.socket, this.buf, Math.min(n, CONFIG.max_preview), 'receive');
          },
        });
      }

      const sendtoFn = Module.findExportByName(moduleName, 'sendto');
      if (sendtoFn) {
        Interceptor.attach(sendtoFn, {
          onEnter(args) {
            const socket = args[0].toInt32();
            const buf = args[1];
            const len = safeToInt(args[2]);
            const peer = parseSockaddr(args[4]);
            if (peer) socketPeerMap[String(socket)] = peer;
            if (len > 0) emitSocketData('sendto', socket, buf, Math.min(len, CONFIG.max_preview), 'send');
          },
        });
      }

      const recvfromFn = Module.findExportByName(moduleName, 'recvfrom');
      if (recvfromFn) {
        Interceptor.attach(recvfromFn, {
          onEnter(args) {
            this.socket = args[0].toInt32();
            this.buf = args[1];
          },
          onLeave(retval) {
            const n = safeToInt(retval);
            if (n > 0) emitSocketData('recvfrom', this.socket, this.buf, Math.min(n, CONFIG.max_preview), 'receive');
          },
        });
      }

      const WSASend = Module.findExportByName(moduleName, 'WSASend');
      if (WSASend) {
        Interceptor.attach(WSASend, {
          onEnter(args) {
            const socket = args[0].toInt32();
            const lpBuffers = args[1];
            const count = safeToInt(args[2]);
            if (!lpBuffers.isNull() && count > 0) {
              try {
                const bufPtr = lpBuffers.readPointer();
                const bufLen = lpBuffers.add(Process.pointerSize).readU32();
                emitSocketData('WSASend', socket, bufPtr, Math.min(bufLen, CONFIG.max_preview), 'send');
              } catch (_) {}
            }
          },
        });
      }

      const WSARecv = Module.findExportByName(moduleName, 'WSARecv');
      if (WSARecv) {
        Interceptor.attach(WSARecv, {
          onEnter(args) {
            this.socket = args[0].toInt32();
            this.lpBuffers = args[1];
          },
          onLeave(retval) {
            // retval 仅表示是否立即完成，实际字节数可能异步，这里只做 best-effort 预览
            try {
              if (this.lpBuffers && !this.lpBuffers.isNull()) {
                const bufPtr = this.lpBuffers.readPointer();
                const bufLen = this.lpBuffers.add(Process.pointerSize).readU32();
                emitSocketData('WSARecv', this.socket, bufPtr, Math.min(bufLen, CONFIG.max_preview), 'receive');
              }
            } catch (_) {}
          },
        });
      }

      sendEvent({ type: 'info', api: 'winsock', message: 'Winsock hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'winsock', message: String(e) });
    }
  }

  // ------------- Crypto (Advapi32 + BCrypt) -------------
  function hookCrypto() {
    try {
      // advapi32 CryptoAPI
      const advapi32 = 'advapi32.dll';
      const CryptEncrypt = Module.findExportByName(advapi32, 'CryptEncrypt');
      if (CryptEncrypt) {
        Interceptor.attach(CryptEncrypt, {
          onEnter(args) {
            const pbData = args[4];
            const pdwDataLen = args[5];
            let dataLen = 0;
            try {
              if (pdwDataLen && !pdwDataLen.isNull()) dataLen = pdwDataLen.readU32();
            } catch (_) {}
            sendEvent({
              type: 'crypto',
              api: 'CryptEncrypt',
              data_length: dataLen,
              data: pbData && dataLen > 0 ? previewBytes(pbData, Math.min(dataLen, CONFIG.max_preview), true) : '',
            }, this.context);
          },
        });
      }

      const CryptDecrypt = Module.findExportByName(advapi32, 'CryptDecrypt');
      if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
          onEnter(args) {
            this.pbData = args[4];
            this.pdwDataLen = args[5];
          },
          onLeave(retval) {
            if (safeToInt(retval) === 0) return;
            let dataLen = 0;
            try {
              if (this.pdwDataLen && !this.pdwDataLen.isNull()) dataLen = this.pdwDataLen.readU32();
            } catch (_) {}
            sendEvent({
              type: 'crypto',
              api: 'CryptDecrypt',
              data_length: dataLen,
              data: this.pbData && dataLen > 0 ? previewBytes(this.pbData, Math.min(dataLen, CONFIG.max_preview), true) : '',
            }, this.context);
          },
        });
      }

      const CryptHashData = Module.findExportByName(advapi32, 'CryptHashData');
      if (CryptHashData) {
        Interceptor.attach(CryptHashData, {
          onEnter(args) {
            const pbData = args[1];
            const dwDataLen = safeToInt(args[2]);
            sendEvent(
              {
                type: 'crypto',
                api: 'CryptHashData',
                data_length: dwDataLen,
                data: pbData && dwDataLen > 0 ? previewBytes(pbData, Math.min(dwDataLen, CONFIG.max_preview), true) : '',
              },
              this.context
            );
          },
        });
      }

      const CryptSignHashW = Module.findExportByName(advapi32, 'CryptSignHashW');
      if (CryptSignHashW) {
        Interceptor.attach(CryptSignHashW, {
          onEnter(args) {
            const alg = safeReadUtf16(args[2]);
            sendEvent({ type: 'crypto', api: 'CryptSignHashW', alg: alg || '' }, this.context);
          },
        });
      }

      // bcrypt CNG
      const bcrypt = 'bcrypt.dll';
      const BCryptEncrypt = Module.findExportByName(bcrypt, 'BCryptEncrypt');
      if (BCryptEncrypt) {
        Interceptor.attach(BCryptEncrypt, {
          onEnter(args) {
            const pbInput = args[2];
            const cbInput = safeToInt(args[3]);
            sendEvent({
              type: 'crypto',
              api: 'BCryptEncrypt',
              input_length: cbInput,
              input: pbInput && cbInput > 0 ? previewBytes(pbInput, Math.min(cbInput, CONFIG.max_preview), true) : '',
            }, this.context);
          },
        });
      }

      const BCryptDecrypt = Module.findExportByName(bcrypt, 'BCryptDecrypt');
      if (BCryptDecrypt) {
        Interceptor.attach(BCryptDecrypt, {
          onEnter(args) {
            const pbInput = args[2];
            const cbInput = safeToInt(args[3]);
            sendEvent({
              type: 'crypto',
              api: 'BCryptDecrypt',
              input_length: cbInput,
              input: pbInput && cbInput > 0 ? previewBytes(pbInput, Math.min(cbInput, CONFIG.max_preview), true) : '',
            }, this.context);
          },
        });
      }

      const BCryptHashData = Module.findExportByName(bcrypt, 'BCryptHashData');
      if (BCryptHashData) {
        Interceptor.attach(BCryptHashData, {
          onEnter(args) {
            const pbInput = args[1];
            const cbInput = safeToInt(args[2]);
            sendEvent(
              {
                type: 'crypto',
                api: 'BCryptHashData',
                input_length: cbInput,
                input: pbInput && cbInput > 0 ? previewBytes(pbInput, Math.min(cbInput, CONFIG.max_preview), true) : '',
              },
              this.context
            );
          },
        });
      }

      const BCryptSignHash = Module.findExportByName(bcrypt, 'BCryptSignHash');
      if (BCryptSignHash) {
        Interceptor.attach(BCryptSignHash, {
          onEnter(args) {
            const pbInput = args[2];
            const cbInput = safeToInt(args[3]);
            sendEvent(
              {
                type: 'crypto',
                api: 'BCryptSignHash',
                input_length: cbInput,
                input: pbInput && cbInput > 0 ? previewBytes(pbInput, Math.min(cbInput, CONFIG.max_preview), true) : '',
              },
              this.context
            );
          },
        });
      }

      sendEvent({ type: 'info', api: 'crypto', message: 'Crypto hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'crypto', message: String(e) });
    }
  }

  // ------------- File/Registry (optional noise) -------------
  function hookFile() {
    try {
      const kernel32 = 'kernel32.dll';
      const CreateFileW = Module.findExportByName(kernel32, 'CreateFileW');
      if (!CreateFileW) return;
      Interceptor.attach(CreateFileW, {
        onEnter(args) {
          const filename = safeReadUtf16(args[0]);
          sendEvent({ type: 'file', api: 'CreateFileW', path: filename });
        },
      });
      sendEvent({ type: 'info', api: 'file', message: 'File hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'file', message: String(e) });
    }
  }

  function hookRegistry() {
    try {
      const advapi32 = 'advapi32.dll';
      const RegOpenKeyExW = Module.findExportByName(advapi32, 'RegOpenKeyExW');
      if (!RegOpenKeyExW) return;
      Interceptor.attach(RegOpenKeyExW, {
        onEnter(args) {
          const subKey = safeReadUtf16(args[1]);
          sendEvent({ type: 'registry', api: 'RegOpenKeyExW', sub_key: subKey });
        },
      });
      sendEvent({ type: 'info', api: 'registry', message: 'Registry hooks installed' });
    } catch (e) {
      sendEvent({ type: 'error', api: 'registry', message: String(e) });
    }
  }

  // ------------- main -------------
  sendEvent({ type: 'info', api: 'script', message: 'Windows API hooks loading', config: CONFIG });

  if (CONFIG.enable_winhttp) hookWinHttp();
  if (CONFIG.enable_wininet) hookWinInet();
  if (CONFIG.enable_winsock) hookWinsock();
  if (CONFIG.enable_crypto) hookCrypto();
  if (CONFIG.enable_file) hookFile();
  if (CONFIG.enable_registry) hookRegistry();

  sendEvent({ type: 'info', api: 'script', message: 'Windows API hooks loaded' });
})();
