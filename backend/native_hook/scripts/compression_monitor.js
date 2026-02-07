/**
 * Compression/Serialization Locator (Windows) - best-effort.
 *
 * 目标：定位“业务数据在网络前最后一次变换”的位置（压缩/解压），辅助排查应用层加密/压缩。
 *
 * 参数（Template.render 替换）：
 * - sample_rate（0~1）
 * - capture_stack_trace（true/false）
 * - max_stack_depth（栈深度）
 * - max_preview（预览长度）
 * - hexdump（true 时使用 hex 预览）
 */
(function () {
  'use strict';

  const CONFIG = {
    sample_rate: {{sample_rate}},
    capture_stack_trace: {{capture_stack_trace}},
    max_stack_depth: {{max_stack_depth}},
    max_preview: {{max_preview}},
    hexdump: {{hexdump}},
  };

  function now() {
    return Date.now();
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

  function previewBytes(ptr, len) {
    const max = Math.max(0, Math.min(len, CONFIG.max_preview || 4096));
    if (!ptr || ptr.isNull() || max <= 0) return '';
    try {
      const buf = ptr.readByteArray(max);
      const bytes = new Uint8Array(buf);
      if (CONFIG.hexdump) return bytesToHex(bytes, max);
      // best-effort utf8
      try {
        return ptr.readUtf8String(max);
      } catch (_) {
        return `<binary ${len} bytes>`;
      }
    } catch (_) {
      return '';
    }
  }

  function sendEvent(payload, context) {
    try {
      const sr = typeof CONFIG.sample_rate === 'number' ? CONFIG.sample_rate : 1;
      if (sr > 0 && sr < 1) {
        if (Math.random() > sr) return;
      }
      maybeAddStack(payload, context);
      payload.timestamp = now();
      send(payload);
    } catch (_) {}
  }

  function hookExport(moduleName, exportName, handlers) {
    try {
      const addr = Module.findExportByName(moduleName, exportName);
      if (!addr) return false;
      Interceptor.attach(addr, handlers);
      return true;
    } catch (_) {
      return false;
    }
  }

  // --------------------------
  // ntdll!RtlCompressBuffer / RtlDecompressBuffer
  // --------------------------
  hookExport('ntdll.dll', 'RtlCompressBuffer', {
    onEnter(args) {
      this.format = args[0];
      this.inPtr = args[1];
      this.inLen = args[2].toInt32();
      this.outPtr = args[3];
      this.outCap = args[4].toInt32();
      this.finalSizePtr = args[6];
      this.inPreview = previewBytes(this.inPtr, this.inLen);
    },
    onLeave(retval) {
      let finalSize = 0;
      try {
        if (this.finalSizePtr && !this.finalSizePtr.isNull()) {
          finalSize = this.finalSizePtr.readU32();
        }
      } catch (_) {}

      sendEvent(
        {
          type: 'compression',
          api: 'RtlCompressBuffer',
          status: retval.toInt32(),
          input_len: this.inLen,
          output_len: finalSize,
          output_cap: this.outCap,
          input_preview: this.inPreview,
          output_preview: previewBytes(this.outPtr, Math.min(finalSize || 0, this.outCap || 0)),
        },
        this.context
      );
    },
  });

  hookExport('ntdll.dll', 'RtlDecompressBuffer', {
    onEnter(args) {
      this.format = args[0];
      this.outPtr = args[1];
      this.outCap = args[2].toInt32();
      this.inPtr = args[3];
      this.inLen = args[4].toInt32();
      this.finalSizePtr = args[5];
      this.inPreview = previewBytes(this.inPtr, this.inLen);
    },
    onLeave(retval) {
      let finalSize = 0;
      try {
        if (this.finalSizePtr && !this.finalSizePtr.isNull()) {
          finalSize = this.finalSizePtr.readU32();
        }
      } catch (_) {}

      sendEvent(
        {
          type: 'compression',
          api: 'RtlDecompressBuffer',
          status: retval.toInt32(),
          input_len: this.inLen,
          output_len: finalSize,
          output_cap: this.outCap,
          input_preview: this.inPreview,
          output_preview: previewBytes(this.outPtr, Math.min(finalSize || 0, this.outCap || 0)),
        },
        this.context
      );
    },
  });

  // --------------------------
  // zlib (if present) - compress2/uncompress
  // --------------------------
  hookExport('zlib1.dll', 'compress2', {
    onEnter(args) {
      this.dest = args[0];
      this.destLenPtr = args[1];
      this.src = args[2];
      this.srcLen = args[3].toInt32();
      this.level = args[4].toInt32();
      this.inPreview = previewBytes(this.src, this.srcLen);
    },
    onLeave(retval) {
      let outLen = 0;
      try {
        outLen = this.destLenPtr.readU32();
      } catch (_) {}
      sendEvent(
        {
          type: 'compression',
          api: 'zlib.compress2',
          status: retval.toInt32(),
          level: this.level,
          input_len: this.srcLen,
          output_len: outLen,
          input_preview: this.inPreview,
          output_preview: previewBytes(this.dest, outLen),
        },
        this.context
      );
    },
  });

  hookExport('zlib1.dll', 'uncompress', {
    onEnter(args) {
      this.dest = args[0];
      this.destLenPtr = args[1];
      this.src = args[2];
      this.srcLen = args[3].toInt32();
      this.inPreview = previewBytes(this.src, this.srcLen);
    },
    onLeave(retval) {
      let outLen = 0;
      try {
        outLen = this.destLenPtr.readU32();
      } catch (_) {}
      sendEvent(
        {
          type: 'compression',
          api: 'zlib.uncompress',
          status: retval.toInt32(),
          input_len: this.srcLen,
          output_len: outLen,
          input_preview: this.inPreview,
          output_preview: previewBytes(this.dest, outLen),
        },
        this.context
      );
    },
  });

  sendEvent({ type: 'info', api: 'compression_monitor', message: 'compression monitor loaded' }, null);
})();
