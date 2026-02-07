/**
 * Windows SSL Unpinning (best-effort)
 *
 * 目标：绕过常见的 Windows 证书校验路径，让流量回到代理侧解密。
 * 覆盖：
 *  - wintrust!WinVerifyTrust
 *  - crypt32!CertVerifyCertificateChainPolicy
 *
 * 注意：不同应用可能使用自研校验/内置证书/第三方 TLS(OpenSSL/BoringSSL)，
 * 本脚本提供的是“通用 Windows API 路径”绕过，不能保证对所有应用生效。
 */

(function () {
  'use strict';

  function log(msg) {
    try {
      console.log('[ssl_unpin] ' + msg);
    } catch (_) {}
  }

  function hookWhenAvailable(moduleName, exportName, onFound) {
    const tryHook = () => {
      try {
        const addr = Module.findExportByName(moduleName, exportName);
        if (!addr) return false;
        onFound(addr);
        return true;
      } catch (e) {
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

  // wintrust!WinVerifyTrust: 返回 0 表示 ERROR_SUCCESS
  hookWhenAvailable('wintrust.dll', 'WinVerifyTrust', (addr) => {
    log('Hooking wintrust!WinVerifyTrust @ ' + addr);
    Interceptor.attach(addr, {
      onLeave(retval) {
        try {
          retval.replace(0);
        } catch (_) {}
      },
    });
  });

  // crypt32!CertVerifyCertificateChainPolicy: 返回 TRUE，并将 pPolicyStatus->dwError 置 0
  hookWhenAvailable('crypt32.dll', 'CertVerifyCertificateChainPolicy', (addr) => {
    log('Hooking crypt32!CertVerifyCertificateChainPolicy @ ' + addr);
    Interceptor.attach(addr, {
      onEnter(args) {
        this.pPolicyStatus = args[3];
      },
      onLeave(retval) {
        try {
          retval.replace(1);
        } catch (_) {}

        try {
          if (this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
            // CERT_CHAIN_POLICY_STATUS.dwError 位于结构体起始处（DWORD）
            this.pPolicyStatus.writeU32(0);
          }
        } catch (_) {}
      },
    });
  });

  log('Loaded');
})();

