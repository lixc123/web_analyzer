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
    
    script_parts.append(JS_HOOK_END)
    
    return ''.join(script_parts)
