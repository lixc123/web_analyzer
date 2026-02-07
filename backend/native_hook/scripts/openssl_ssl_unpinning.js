/**
 * OpenSSL/BoringSSL SSL Unpinning (best-effort)
 *
 * 目标：覆盖使用 OpenSSL/BoringSSL 的应用（非 Windows Schannel 路径）。
 * 说明：不同版本/导出符号差异很大，本脚本做 best-effort：
 *  - 强制 SSL_get_verify_result() 返回 X509_V_OK(0)
 *  - 强制 X509_verify_cert() 返回 1
 */

(function () {
  'use strict';

  function log(msg) {
    try {
      console.log('[openssl_unpin] ' + msg);
    } catch (_) {}
  }

  function hookExport(moduleName, exportName, onHook) {
    try {
      const addr = Module.findExportByName(moduleName, exportName);
      if (!addr) return false;
      onHook(addr);
      log(`Hooked ${moduleName}!${exportName} @ ${addr}`);
      return true;
    } catch (_) {
      return false;
    }
  }

  function tryHookInModule(moduleName) {
    let ok = false;

    ok =
      hookExport(moduleName, 'SSL_get_verify_result', (addr) => {
        Interceptor.attach(addr, {
          onLeave(retval) {
            try {
              retval.replace(0);
            } catch (_) {}
          },
        });
      }) || ok;

    ok =
      hookExport(moduleName, 'X509_verify_cert', (addr) => {
        Interceptor.attach(addr, {
          onLeave(retval) {
            try {
              retval.replace(1);
            } catch (_) {}
          },
        });
      }) || ok;

    // 部分库提供 verify 回调设置函数，尽量弱干预（仅记录）
    hookExport(moduleName, 'SSL_CTX_set_verify', (addr) => {
      Interceptor.attach(addr, {
        onEnter(args) {
          // args[1]=mode, args[2]=callback
          log(`SSL_CTX_set_verify(mode=${args[1]})`);
        },
      });
    });
    hookExport(moduleName, 'SSL_set_verify', (addr) => {
      Interceptor.attach(addr, {
        onEnter(args) {
          log(`SSL_set_verify(mode=${args[1]})`);
        },
      });
    });

    return ok;
  }

  function main() {
    const modules = Process.enumerateModules();
    const candidates = modules
      .map((m) => m.name)
      .filter((n) => /ssl|boringssl|crypto/i.test(n));

    const seen = {};
    let hookedAny = false;
    candidates.forEach((name) => {
      if (seen[name]) return;
      seen[name] = true;
      if (tryHookInModule(name)) hookedAny = true;
    });

    if (!hookedAny) {
      log('No OpenSSL/BoringSSL exports found (best-effort).');
    } else {
      log('Loaded.');
    }
  }

  main();
})();

