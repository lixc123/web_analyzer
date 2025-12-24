JS_HOOK_SCRIPT = """
// ============================================
// Web Analyzer V2 - 综合浏览器数据录制钩子
// ============================================

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

    // ============================================
    // 1. 网络请求拦截（增强版）
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

    // XMLHttpRequest 拦截（增强版）
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

    // ============================================
    // 2. 浏览器存储数据拦截
    // ============================================
    
    // localStorage 拦截
    const originalLocalStorage = {
        setItem: localStorage.setItem,
        getItem: localStorage.getItem,
        removeItem: localStorage.removeItem,
        clear: localStorage.clear
    };
    
    localStorage.setItem = function(key, value) {
        logEvent('LOCALSTORAGE_SET', {
            key: key,
            value: value,
            stack: getStack()
        });
        return originalLocalStorage.setItem.call(this, key, value);
    };
    
    localStorage.removeItem = function(key) {
        logEvent('LOCALSTORAGE_REMOVE', {
            key: key,
            stack: getStack()
        });
        return originalLocalStorage.removeItem.call(this, key);
    };
    
    localStorage.clear = function() {
        logEvent('LOCALSTORAGE_CLEAR', {
            stack: getStack()
        });
        return originalLocalStorage.clear.call(this);
    };
    
    // sessionStorage 拦截
    const originalSessionStorage = {
        setItem: sessionStorage.setItem,
        getItem: sessionStorage.getItem,
        removeItem: sessionStorage.removeItem,
        clear: sessionStorage.clear
    };
    
    sessionStorage.setItem = function(key, value) {
        logEvent('SESSIONSTORAGE_SET', {
            key: key,
            value: value,
            stack: getStack()
        });
        return originalSessionStorage.setItem.call(this, key, value);
    };
    
    sessionStorage.removeItem = function(key) {
        logEvent('SESSIONSTORAGE_REMOVE', {
            key: key,
            stack: getStack()
        });
        return originalSessionStorage.removeItem.call(this, key);
    };
    
    sessionStorage.clear = function() {
        logEvent('SESSIONSTORAGE_CLEAR', {
            stack: getStack()
        });
        return originalSessionStorage.clear.call(this);
    };

    // IndexedDB 拦截
    const originalIndexedDB = {
        open: indexedDB.open,
        deleteDatabase: indexedDB.deleteDatabase
    };
    
    indexedDB.open = function(name, version) {
        logEvent('INDEXEDDB_OPEN', {
            databaseName: name,
            version: version,
            stack: getStack()
        });
        
        const request = originalIndexedDB.open.call(this, name, version);
        
        request.addEventListener('success', (event) => {
            logEvent('INDEXEDDB_OPENED', {
                databaseName: name,
                version: event.target.result.version
            });
        });
        
        return request;
    };

    // ============================================
    // 3. 用户交互事件跟踪
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
                coordinates: {
                    x: event.clientX,
                    y: event.clientY
                },
                url: window.location.href,
                stack: getStack()
            });
        };
    };
    
    // 添加交互事件监听器
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

    // ============================================
    // 4. 表单数据跟踪
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

    // ============================================
    // 5. DOM 变化监控
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
                    addedNodes: Array.from(mutation.addedNodes).map(node => ({
                        nodeType: node.nodeType,
                        tagName: node.tagName,
                        textContent: node.textContent?.substring(0, 100)
                    })),
                    url: window.location.href
                });
            }
        });
    });
    
    domObserver.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: false,
        characterData: false
    });

    // ============================================
    // 6. 导航历史跟踪
    // ============================================
    
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(state, title, url) {
        logEvent('HISTORY_PUSH', {
            state: state,
            title: title,
            url: url,
            stack: getStack()
        });
        return originalPushState.call(this, state, title, url);
    };
    
    history.replaceState = function(state, title, url) {
        logEvent('HISTORY_REPLACE', {
            state: state,
            title: title,
            url: url,
            stack: getStack()
        });
        return originalReplaceState.call(this, state, title, url);
    };
    
    window.addEventListener('popstate', function(event) {
        logEvent('HISTORY_POP', {
            state: event.state,
            url: window.location.href
        });
    });

    // ============================================
    // 7. Console 日志增强拦截
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
            logEvent('CONSOLE_OUTPUT', {
                level: method,
                args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)),
                stack: getStack()
            });
            return originalConsole[method].apply(this, args);
        };
    });

    // ============================================
    // 8. 性能数据监控
    // ============================================
    
    window.addEventListener('load', function() {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            logEvent('PERFORMANCE_NAVIGATION', {
                loadEventEnd: perfData.loadEventEnd,
                domContentLoadedEventEnd: perfData.domContentLoadedEventEnd,
                responseEnd: perfData.responseEnd,
                domComplete: perfData.domComplete,
                url: window.location.href
            });
            
            const resourceEntries = performance.getEntriesByType('resource');
            resourceEntries.forEach(entry => {
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

    // ============================================
    // 9. 初始化数据快照
    // ============================================
    
    // 页面加载时记录初始状态
    window.addEventListener('DOMContentLoaded', function() {
        // 记录初始 localStorage
        const localStorageData = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            localStorageData[key] = localStorage.getItem(key);
        }
        logEvent('INITIAL_LOCALSTORAGE', localStorageData);
        
        // 记录初始 sessionStorage
        const sessionStorageData = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            sessionStorageData[key] = sessionStorage.getItem(key);
        }
        logEvent('INITIAL_SESSIONSTORAGE', sessionStorageData);
        
        // 记录页面基本信息
        logEvent('PAGE_INFO', {
            url: window.location.href,
            title: document.title,
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight
            }
        });
    });

    // 定期记录 DOM 快照（简化版）
    setInterval(() => {
        logEvent('DOM_SNAPSHOT', {
            url: window.location.href,
            title: document.title,
            bodyHTML: document.body?.innerHTML?.length || 0, // 只记录长度，避免过大
            forms: Array.from(document.forms).map(form => ({
                id: form.id,
                action: form.action,
                method: form.method,
                elements: form.elements.length
            }))
        });
    }, 30000); // 每30秒记录一次

    console.log('[WEB_RECORDER_INITIALIZED]', 'Comprehensive browser data recording is active');
})();
"""
