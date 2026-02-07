/**
 * mbedTLS SSL Unpinning (best-effort)
 *
 * 覆盖使用 mbedTLS 的应用（常见于某些跨平台 SDK）。
 * - mbedtls_x509_crt_verify / mbedtls_x509_crt_verify_with_profile 返回 0 表示校验成功
 */

(function () {
  'use strict';

  function log(msg) {
    try {
      console.log('[mbedtls_unpin] ' + msg);
    } catch (_) {}
  }

  function hookWhenAvailable(moduleName, exportName, onFound) {
    const tryHook = () => {
      try {
        const addr = Module.findExportByName(moduleName, exportName);
        if (!addr) return false;
        onFound(addr);
        log(`Hooked ${moduleName}!${exportName} @ ${addr}`);
        return true;
      } catch (_) {
        return false;
      }
    };

    if (tryHook()) return;

    const timer = setInterval(() => {
      if (tryHook()) {
        clearInterval(timer);
      }
    }, 500);
  }

  function hookVerify(moduleName, exportName) {
    hookWhenAvailable(moduleName, exportName, (addr) => {
      Interceptor.attach(addr, {
        onLeave(retval) {
          try {
            retval.replace(0);
          } catch (_) {}
        },
      });
    });
  }

  function main() {
    const modules = Process.enumerateModules();
    const candidates = modules.map((m) => m.name).filter((n) => /mbedtls/i.test(n));

    if (candidates.length === 0) {
      log('No mbedTLS module found.');
      return;
    }

    const seen = {};
    candidates.forEach((name) => {
      if (seen[name]) return;
      seen[name] = true;
      hookVerify(name, 'mbedtls_x509_crt_verify');
      hookVerify(name, 'mbedtls_x509_crt_verify_with_profile');
    });

    log('Loaded.');
  }

  main();
})();

