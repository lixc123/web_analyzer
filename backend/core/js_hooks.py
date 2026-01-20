# JS Hook 脚本模块化生成器
# 根据用户配置动态生成需要的 Hook 代码

# 基础框架代码
JS_HOOK_BASE = """
(function() {
    'use strict';
    
    const timestamp = () => Date.now();
    const getStack = () => new Error().stack;
    const logEvent = (type, data) => {
        console.log(`[WEB_RECORDER_${type}]`, JSON.stringify({
            timestamp: timestamp(),
            ...data
        }));
    };
"""

# 网络请求拦截模块 (fetch/XHR)
JS_HOOK_NETWORK = """
    // ============================================
    // 网络请求拦截（Fetch + XHR）
    // ============================================
    
    // Fetch API 拦截
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const startTime = timestamp();
        const stack = getStack();
        const url = typeof args[0] === 'string' ? args[0] : args[0].url;
        const options = args[1] || {};
        
        logEvent('FETCH_START', {
            url: url,
            method: options.method || 'GET',
            headers: options.headers,
            body: options.body,
            stack: stack,
            startTime: startTime
        });
        
        try {
            const response = await originalFetch.apply(this, args);
            logEvent('FETCH_RESPONSE', {
                url: url,
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                duration: timestamp() - startTime
            });
            return response;
        } catch (error) {
            logEvent('FETCH_ERROR', {
                url: url,
                error: error.message,
                duration: timestamp() - startTime
            });
            throw error;
        }
    };

    // XMLHttpRequest 拦截
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._hookData = {
            method: method,
            url: url,
            startTime: timestamp(),
            stack: getStack(),
            headers: {}
        };
        return originalXHROpen.call(this, method, url, ...rest);
    };
    
    XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
        if (this._hookData) {
            this._hookData.headers[header] = value;
        }
        return originalXHRSetRequestHeader.call(this, header, value);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
        if (this._hookData) {
            logEvent('XHR_START', {
                method: this._hookData.method,
                url: this._hookData.url,
                headers: this._hookData.headers,
                body: body,
                stack: this._hookData.stack,
                startTime: this._hookData.startTime
            });
            
            this.addEventListener('load', () => {
                logEvent('XHR_RESPONSE', {
                    url: this._hookData.url,
                    status: this.status,
                    statusText: this.statusText,
                    responseHeaders: this.getAllResponseHeaders(),
                    duration: timestamp() - this._hookData.startTime
                });
            });
            
            this.addEventListener('error', () => {
                logEvent('XHR_ERROR', {
                    url: this._hookData.url,
                    duration: timestamp() - this._hookData.startTime
                });
            });
        }
        return originalXHRSend.call(this, body);
    };
"""

# 存储拦截模块 (localStorage/sessionStorage/IndexedDB)
JS_HOOK_STORAGE = """
    // ============================================
    // 浏览器存储数据拦截
    // ============================================
    
    // localStorage 拦截
    const originalLocalStorage = {
        setItem: localStorage.setItem,
        removeItem: localStorage.removeItem,
        clear: localStorage.clear
    };
    
    localStorage.setItem = function(key, value) {
        logEvent('LOCALSTORAGE_SET', { key: key, value: value, stack: getStack() });
        return originalLocalStorage.setItem.call(this, key, value);
    };
    
    localStorage.removeItem = function(key) {
        logEvent('LOCALSTORAGE_REMOVE', { key: key, stack: getStack() });
        return originalLocalStorage.removeItem.call(this, key);
    };
    
    localStorage.clear = function() {
        logEvent('LOCALSTORAGE_CLEAR', { stack: getStack() });
        return originalLocalStorage.clear.call(this);
    };
    
    // sessionStorage 拦截
    const originalSessionStorage = {
        setItem: sessionStorage.setItem,
        removeItem: sessionStorage.removeItem,
        clear: sessionStorage.clear
    };
    
    sessionStorage.setItem = function(key, value) {
        logEvent('SESSIONSTORAGE_SET', { key: key, value: value, stack: getStack() });
        return originalSessionStorage.setItem.call(this, key, value);
    };
    
    sessionStorage.removeItem = function(key) {
        logEvent('SESSIONSTORAGE_REMOVE', { key: key, stack: getStack() });
        return originalSessionStorage.removeItem.call(this, key);
    };
    
    sessionStorage.clear = function() {
        logEvent('SESSIONSTORAGE_CLEAR', { stack: getStack() });
        return originalSessionStorage.clear.call(this);
    };

    // IndexedDB 拦截
    const originalIndexedDBOpen = indexedDB.open;
    indexedDB.open = function(name, version) {
        logEvent('INDEXEDDB_OPEN', { databaseName: name, version: version, stack: getStack() });
        const request = originalIndexedDBOpen.call(this, name, version);
        request.addEventListener('success', (event) => {
            logEvent('INDEXEDDB_OPENED', { databaseName: name, version: event.target.result.version });
        });
        return request;
    };
"""

# 用户交互跟踪模块
JS_HOOK_USER_INTERACTION = """
    // ============================================
    // 用户交互事件跟踪
    // ============================================
    
    const trackUserInteraction = (eventType) => {
        return function(event) {
            logEvent('USER_INTERACTION', {
                type: eventType,
                target: {
                    tagName: event.target.tagName,
                    id: event.target.id,
                    className: event.target.className,
                    innerText: event.target.innerText?.substring(0, 100)
                },
                coordinates: { x: event.clientX, y: event.clientY },
                url: window.location.href,
                stack: getStack()
            });
        };
    };
    
    ['click', 'dblclick', 'mousedown', 'mouseup', 'keydown', 'keyup', 'input', 'change', 'submit'].forEach(eventType => {
        document.addEventListener(eventType, trackUserInteraction(eventType), true);
    });
    
    // 滚动事件（节流处理）
    let scrollTimeout;
    document.addEventListener('scroll', function(event) {
        if (scrollTimeout) return;
        scrollTimeout = setTimeout(() => {
            logEvent('USER_INTERACTION', {
                type: 'scroll',
                scrollY: window.scrollY,
                scrollX: window.scrollX,
                url: window.location.href
            });
            scrollTimeout = null;
        }, 200);
    }, true);
"""

# 表单数据跟踪模块
JS_HOOK_FORM = """
    // ============================================
    // 表单数据跟踪
    // ============================================
    
    document.addEventListener('input', function(event) {
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA' || event.target.tagName === 'SELECT') {
            logEvent('FORM_INPUT', {
                type: event.target.type,
                name: event.target.name,
                value: event.target.type === 'password' ? '[PASSWORD]' : event.target.value?.substring(0, 100),
                placeholder: event.target.placeholder,
                formId: event.target.form?.id,
                stack: getStack()
            });
        }
    }, true);
    
    document.addEventListener('submit', function(event) {
        const formData = new FormData(event.target);
        const formValues = {};
        for (let [key, value] of formData.entries()) {
            formValues[key] = typeof value === 'string' ? value.substring(0, 100) : '[FILE]';
        }
        logEvent('FORM_SUBMIT', {
            action: event.target.action,
            method: event.target.method,
            formData: formValues,
            stack: getStack()
        });
    }, true);
"""

# DOM 变化监控模块
JS_HOOK_DOM = """
    // ============================================
    // DOM 变化监控
    // ============================================
    
    const domObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                logEvent('DOM_CHANGE', {
                    type: mutation.type,
                    target: {
                        tagName: mutation.target.tagName,
                        id: mutation.target.id,
                        className: mutation.target.className
                    },
                    addedNodes: Array.from(mutation.addedNodes).slice(0, 5).map(node => ({
                        nodeType: node.nodeType,
                        tagName: node.tagName,
                        textContent: node.textContent?.substring(0, 50)
                    })),
                    url: window.location.href
                });
            }
        });
    });
    
    if (document.body) {
        domObserver.observe(document.body, { childList: true, subtree: true });
    }
"""

# 导航历史跟踪模块
JS_HOOK_NAVIGATION = """
    // ============================================
    // 导航历史跟踪
    // ============================================
    
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(state, title, url) {
        logEvent('HISTORY_PUSH', { state: state, title: title, url: url, stack: getStack() });
        return originalPushState.call(this, state, title, url);
    };
    
    history.replaceState = function(state, title, url) {
        logEvent('HISTORY_REPLACE', { state: state, title: title, url: url, stack: getStack() });
        return originalReplaceState.call(this, state, title, url);
    };
    
    window.addEventListener('popstate', function(event) {
        logEvent('HISTORY_POP', { state: event.state, url: window.location.href });
    });
"""

# Console 日志拦截模块
JS_HOOK_CONSOLE = """
    // ============================================
    // Console 日志拦截
    // ============================================
    
    const originalConsole = {
        log: console.log,
        warn: console.warn,
        error: console.error,
        info: console.info,
        debug: console.debug
    };
    
    Object.keys(originalConsole).forEach(method => {
        console[method] = function(...args) {
            // 避免递归：不记录我们自己的日志
            const firstArg = args[0];
            if (typeof firstArg === 'string' && firstArg.startsWith('[WEB_RECORDER_')) {
                return originalConsole[method].apply(this, args);
            }
            logEvent('CONSOLE_OUTPUT', {
                level: method,
                args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)),
                stack: getStack()
            });
            return originalConsole[method].apply(this, args);
        };
    });
"""

# 性能数据监控模块
JS_HOOK_PERFORMANCE = """
    // ============================================
    // 性能数据监控
    // ============================================

    window.addEventListener('load', function() {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            if (perfData) {
                logEvent('PERFORMANCE_NAVIGATION', {
                    loadEventEnd: perfData.loadEventEnd,
                    domContentLoadedEventEnd: perfData.domContentLoadedEventEnd,
                    responseEnd: perfData.responseEnd,
                    domComplete: perfData.domComplete,
                    url: window.location.href
                });
            }

            const resourceEntries = performance.getEntriesByType('resource');
            resourceEntries.slice(0, 50).forEach(entry => {
                logEvent('PERFORMANCE_RESOURCE', {
                    name: entry.name,
                    duration: entry.duration,
                    transferSize: entry.transferSize,
                    encodedBodySize: entry.encodedBodySize,
                    decodedBodySize: entry.decodedBodySize
                });
            });
        }, 1000);
    });
"""

# WebSocket拦截模块
JS_HOOK_WEBSOCKET = """
    // ============================================
    // WebSocket拦截
    // ============================================

    const OriginalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        const ws = new OriginalWebSocket(url, protocols);
        const wsId = `ws_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

        logEvent('WEBSOCKET_CONNECT', {
            id: wsId,
            url: url,
            protocols: protocols,
            stack: getStack()
        });

        // Hook onopen
        const originalOnOpen = ws.onopen;
        ws.onopen = function(event) {
            logEvent('WEBSOCKET_OPEN', {
                id: wsId,
                url: url
            });
            if (originalOnOpen) originalOnOpen.call(this, event);
        };

        // Hook onmessage
        const originalOnMessage = ws.onmessage;
        ws.onmessage = function(event) {
            let data = event.data;
            let dataPreview = data;

            // 处理不同类型的数据
            if (data instanceof Blob) {
                dataPreview = `[Blob ${data.size} bytes]`;
            } else if (data instanceof ArrayBuffer) {
                dataPreview = `[ArrayBuffer ${data.byteLength} bytes]`;
            } else if (typeof data === 'string') {
                dataPreview = data.length > 1000 ? data.substring(0, 1000) + '...' : data;
            }

            logEvent('WEBSOCKET_MESSAGE', {
                id: wsId,
                url: url,
                direction: 'receive',
                data: dataPreview,
                dataType: data instanceof Blob ? 'blob' : data instanceof ArrayBuffer ? 'arraybuffer' : 'string',
                size: data.length || data.size || data.byteLength || 0
            });

            if (originalOnMessage) originalOnMessage.call(this, event);
        };

        // Hook send
        const originalSend = ws.send;
        ws.send = function(data) {
            let dataPreview = data;

            if (data instanceof Blob) {
                dataPreview = `[Blob ${data.size} bytes]`;
            } else if (data instanceof ArrayBuffer) {
                dataPreview = `[ArrayBuffer ${data.byteLength} bytes]`;
            } else if (typeof data === 'string') {
                dataPreview = data.length > 1000 ? data.substring(0, 1000) + '...' : data;
            }

            logEvent('WEBSOCKET_MESSAGE', {
                id: wsId,
                url: url,
                direction: 'send',
                data: dataPreview,
                dataType: data instanceof Blob ? 'blob' : data instanceof ArrayBuffer ? 'arraybuffer' : 'string',
                size: data.length || data.size || data.byteLength || 0,
                stack: getStack()
            });

            return originalSend.call(this, data);
        };

        // Hook onerror
        const originalOnError = ws.onerror;
        ws.onerror = function(event) {
            logEvent('WEBSOCKET_ERROR', {
                id: wsId,
                url: url
            });
            if (originalOnError) originalOnError.call(this, event);
        };

        // Hook onclose
        const originalOnClose = ws.onclose;
        ws.onclose = function(event) {
            logEvent('WEBSOCKET_CLOSE', {
                id: wsId,
                url: url,
                code: event.code,
                reason: event.reason,
                wasClean: event.wasClean
            });
            if (originalOnClose) originalOnClose.call(this, event);
        };

        return ws;
    };

    // 保留原始WebSocket的属性
    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
"""

# Crypto API拦截模块
JS_HOOK_CRYPTO = """
    // ============================================
    // Crypto API拦截
    // ============================================

    if (window.crypto && window.crypto.subtle) {
        const originalSubtle = window.crypto.subtle;

        // Helper: 转换ArrayBuffer为hex字符串
        const bufferToHex = (buffer) => {
            if (!buffer) return '';
            const bytes = new Uint8Array(buffer);
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 100);
        };

        // Hook encrypt
        const originalEncrypt = originalSubtle.encrypt;
        originalSubtle.encrypt = async function(algorithm, key, data) {
            const cryptoId = `crypto_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

            logEvent('CRYPTO_ENCRYPT', {
                id: cryptoId,
                algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name,
                dataSize: data.byteLength,
                dataPreview: bufferToHex(data),
                stack: getStack()
            });

            try {
                const result = await originalEncrypt.call(this, algorithm, key, data);
                logEvent('CRYPTO_ENCRYPT_RESULT', {
                    id: cryptoId,
                    resultSize: result.byteLength,
                    resultPreview: bufferToHex(result)
                });
                return result;
            } catch (error) {
                logEvent('CRYPTO_ENCRYPT_ERROR', {
                    id: cryptoId,
                    error: error.message
                });
                throw error;
            }
        };

        // Hook decrypt
        const originalDecrypt = originalSubtle.decrypt;
        originalSubtle.decrypt = async function(algorithm, key, data) {
            const cryptoId = `crypto_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

            logEvent('CRYPTO_DECRYPT', {
                id: cryptoId,
                algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name,
                dataSize: data.byteLength,
                dataPreview: bufferToHex(data),
                stack: getStack()
            });

            try {
                const result = await originalDecrypt.call(this, algorithm, key, data);
                logEvent('CRYPTO_DECRYPT_RESULT', {
                    id: cryptoId,
                    resultSize: result.byteLength,
                    resultPreview: bufferToHex(result)
                });
                return result;
            } catch (error) {
                logEvent('CRYPTO_DECRYPT_ERROR', {
                    id: cryptoId,
                    error: error.message
                });
                throw error;
            }
        };

        // Hook digest
        const originalDigest = originalSubtle.digest;
        originalSubtle.digest = async function(algorithm, data) {
            const cryptoId = `crypto_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

            logEvent('CRYPTO_DIGEST', {
                id: cryptoId,
                algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name,
                dataSize: data.byteLength,
                dataPreview: bufferToHex(data),
                stack: getStack()
            });

            try {
                const result = await originalDigest.call(this, algorithm, data);
                logEvent('CRYPTO_DIGEST_RESULT', {
                    id: cryptoId,
                    hash: bufferToHex(result)
                });
                return result;
            } catch (error) {
                logEvent('CRYPTO_DIGEST_ERROR', {
                    id: cryptoId,
                    error: error.message
                });
                throw error;
            }
        };

        // Hook sign
        const originalSign = originalSubtle.sign;
        originalSubtle.sign = async function(algorithm, key, data) {
            const cryptoId = `crypto_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

            logEvent('CRYPTO_SIGN', {
                id: cryptoId,
                algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name,
                dataSize: data.byteLength,
                dataPreview: bufferToHex(data),
                stack: getStack()
            });

            try {
                const result = await originalSign.call(this, algorithm, key, data);
                logEvent('CRYPTO_SIGN_RESULT', {
                    id: cryptoId,
                    signatureSize: result.byteLength,
                    signaturePreview: bufferToHex(result)
                });
                return result;
            } catch (error) {
                logEvent('CRYPTO_SIGN_ERROR', {
                    id: cryptoId,
                    error: error.message
                });
                throw error;
            }
        };

        // Hook verify
        const originalVerify = originalSubtle.verify;
        originalSubtle.verify = async function(algorithm, key, signature, data) {
            const cryptoId = `crypto_${timestamp()}_${Math.random().toString(36).substr(2, 9)}`;

            logEvent('CRYPTO_VERIFY', {
                id: cryptoId,
                algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name,
                signatureSize: signature.byteLength,
                dataSize: data.byteLength,
                stack: getStack()
            });

            try {
                const result = await originalVerify.call(this, algorithm, key, signature, data);
                logEvent('CRYPTO_VERIFY_RESULT', {
                    id: cryptoId,
                    valid: result
                });
                return result;
            } catch (error) {
                logEvent('CRYPTO_VERIFY_ERROR', {
                    id: cryptoId,
                    error: error.message
                });
                throw error;
            }
        };

        // Hook getRandomValues
        const originalGetRandomValues = window.crypto.getRandomValues;
        window.crypto.getRandomValues = function(array) {
            logEvent('CRYPTO_RANDOM', {
                length: array.length,
                type: array.constructor.name,
                stack: getStack()
            });
            return originalGetRandomValues.call(this, array);
        };
    }
"""

# 存储数据完整导出模块
JS_HOOK_STORAGE_EXPORT = """
    // ============================================
    // 存储数据完整导出
    // ============================================

    // 导出localStorage完整数据
    const exportLocalStorage = () => {
        const data = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            data[key] = localStorage.getItem(key);
        }
        return data;
    };

    // 导出sessionStorage完整数据
    const exportSessionStorage = () => {
        const data = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            data[key] = sessionStorage.getItem(key);
        }
        return data;
    };

    // 导出Cookies
    const exportCookies = () => {
        return document.cookie.split(';').map(cookie => {
            const [name, ...valueParts] = cookie.trim().split('=');
            return {
                name: name,
                value: valueParts.join('=')
            };
        }).filter(c => c.name);
    };

    // 导出IndexedDB数据
    const exportIndexedDB = async () => {
        const databases = await indexedDB.databases();
        const result = {};

        for (const dbInfo of databases) {
            try {
                const db = await new Promise((resolve, reject) => {
                    const request = indexedDB.open(dbInfo.name);
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });

                const stores = Array.from(db.objectStoreNames);
                result[dbInfo.name] = {
                    version: db.version,
                    stores: stores,
                    data: {}
                };

                for (const storeName of stores) {
                    const tx = db.transaction(storeName, 'readonly');
                    const store = tx.objectStore(storeName);
                    const allData = await new Promise((resolve, reject) => {
                        const request = store.getAll();
                        request.onsuccess = () => resolve(request.result);
                        request.onerror = () => reject(request.error);
                    });
                    result[dbInfo.name].data[storeName] = allData;
                }

                db.close();
            } catch (error) {
                result[dbInfo.name] = { error: error.message };
            }
        }

        return result;
    };

    // 页面加载完成后导出所有存储数据
    window.addEventListener('load', async function() {
        setTimeout(async () => {
            try {
                const storageData = {
                    localStorage: exportLocalStorage(),
                    sessionStorage: exportSessionStorage(),
                    cookies: exportCookies(),
                    indexedDB: await exportIndexedDB()
                };

                logEvent('STORAGE_EXPORT', {
                    localStorageKeys: Object.keys(storageData.localStorage).length,
                    sessionStorageKeys: Object.keys(storageData.sessionStorage).length,
                    cookiesCount: storageData.cookies.length,
                    indexedDBCount: Object.keys(storageData.indexedDB).length,
                    data: storageData
                });
            } catch (error) {
                logEvent('STORAGE_EXPORT_ERROR', {
                    error: error.message
                });
            }
        }, 2000);
    });
"""

# 状态管理Hook（Redux/Vuex/Pinia等）
JS_HOOK_STATE_MANAGEMENT = """
    // Hook Redux DevTools
    (function() {
        const origDefineProperty = Object.defineProperty;
        Object.defineProperty = function(obj, prop, descriptor) {
            if (prop === '__REDUX_DEVTOOLS_EXTENSION__' || prop === 'devToolsExtension') {
                const origGet = descriptor.get;
                descriptor.get = function() {
                    const devTools = origGet ? origGet.call(this) : undefined;
                    if (devTools && devTools.connect) {
                        const origConnect = devTools.connect;
                        devTools.connect = function(options) {
                            const instance = origConnect.call(this, options);
                            const origSubscribe = instance.subscribe;
                            instance.subscribe = function(listener) {
                                return origSubscribe.call(this, function(message) {
                                    if (message.type === 'DISPATCH' && message.state) {
                                        console.log('[STATE_REDUX]', JSON.stringify({
                                            timestamp: Date.now(),
                                            state: message.state,
                                            action: message.payload
                                        }));
                                    }
                                    return listener(message);
                                });
                            };
                            return instance;
                        };
                    }
                    return devTools;
                };
            }
            return origDefineProperty.call(this, obj, prop, descriptor);
        };
    })();

    // Hook Vuex
    if (window.Vue && window.Vuex) {
        const origInstall = window.Vuex.Store.prototype.commit;
        window.Vuex.Store.prototype.commit = function(type, payload) {
            console.log('[STATE_VUEX]', JSON.stringify({
                timestamp: Date.now(),
                mutation: type,
                payload: payload,
                state: this.state
            }));
            return origInstall.call(this, type, payload);
        };
    }

    // Hook Pinia
    setTimeout(() => {
        if (window.__PINIA__) {
            const stores = window.__PINIA__.state.value;
            Object.keys(stores).forEach(key => {
                console.log('[STATE_PINIA]', JSON.stringify({
                    timestamp: Date.now(),
                    store: key,
                    state: stores[key]
                }));
            });
        }
    }, 1000);

    // 全局变量快照
    setTimeout(() => {
        const globalSnapshot = {};
        ['__INITIAL_STATE__', '__PRELOADED_STATE__', 'APP_STATE', 'GLOBAL_CONFIG'].forEach(key => {
            if (window[key]) globalSnapshot[key] = window[key];
        });
        if (Object.keys(globalSnapshot).length > 0) {
            console.log('[STATE_GLOBAL]', JSON.stringify({
                timestamp: Date.now(),
                snapshot: globalSnapshot
            }));
        }
    }, 500);
"""

# 结束代码
JS_HOOK_END = """
    console.log('[WEB_RECORDER_INITIALIZED]', 'Browser data recording is active');
})();
"""

# 默认完整脚本（向后兼容）
JS_HOOK_SCRIPT = (
    JS_HOOK_BASE +
    JS_HOOK_NETWORK +
    JS_HOOK_STORAGE +
    JS_HOOK_USER_INTERACTION +
    JS_HOOK_FORM +
    JS_HOOK_DOM +
    JS_HOOK_NAVIGATION +
    JS_HOOK_CONSOLE +
    JS_HOOK_PERFORMANCE +
    JS_HOOK_END
)


def generate_hook_script(options: dict = None) -> str:
    """
    根据配置选项生成 JS Hook 脚本

    Args:
        options: Hook 选项字典，包含以下键：
            - network: 网络请求拦截 (fetch/XHR)
            - storage: 存储拦截 (localStorage/sessionStorage/IndexedDB)
            - userInteraction: 用户交互跟踪
            - form: 表单数据跟踪
            - dom: DOM变化监控
            - navigation: 导航历史跟踪
            - console: Console日志拦截
            - performance: 性能数据监控
            - websocket: WebSocket拦截
            - crypto: Crypto API拦截
            - storageExport: 存储数据完整导出
            - stateManagement: 状态管理拦截 (Redux/Vuex/Pinia)

    Returns:
        生成的 JS Hook 脚本字符串
    """
    if options is None:
        # 默认只开启网络请求
        options = {'network': True}

    # 检查是否所有选项都关闭
    if not any(options.values()):
        return ""  # 不注入任何脚本

    script_parts = [JS_HOOK_BASE]

    if options.get('network', False):
        script_parts.append(JS_HOOK_NETWORK)

    if options.get('storage', False):
        script_parts.append(JS_HOOK_STORAGE)

    if options.get('userInteraction', False):
        script_parts.append(JS_HOOK_USER_INTERACTION)

    if options.get('form', False):
        script_parts.append(JS_HOOK_FORM)

    if options.get('dom', False):
        script_parts.append(JS_HOOK_DOM)

    if options.get('navigation', False):
        script_parts.append(JS_HOOK_NAVIGATION)

    if options.get('console', False):
        script_parts.append(JS_HOOK_CONSOLE)

    if options.get('performance', False):
        script_parts.append(JS_HOOK_PERFORMANCE)

    if options.get('websocket', False):
        script_parts.append(JS_HOOK_WEBSOCKET)

    if options.get('crypto', False):
        script_parts.append(JS_HOOK_CRYPTO)

    if options.get('storageExport', False):
        script_parts.append(JS_HOOK_STORAGE_EXPORT)

    if options.get('stateManagement', False):
        script_parts.append(JS_HOOK_STATE_MANAGEMENT)

    script_parts.append(JS_HOOK_END)

    return ''.join(script_parts)
