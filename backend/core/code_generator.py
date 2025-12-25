"""
HTTP请求到Python代码的转换器

将录制的RequestRecord转换为可直接执行的Python代码，用于AI分析时运行验证。
"""

import json
import hashlib
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from models.request_record import RequestRecord
from .js_converter_simple import enhance_code_with_js_analysis
import asyncio
from concurrent.futures import ThreadPoolExecutor


class PythonCodeGenerator:
    """将HTTP请求记录转换为Python代码的生成器"""
    
    def __init__(self):
        self.session_name = ""
        self.imports = set()
        self.helper_functions = set()
        
    def generate_session_code(self, records: List[RequestRecord], session_path: Path) -> str:
        """生成整个会话的Python代码"""
        if not records:
            return "# 没有找到HTTP请求记录\nprint('No requests found')\n"
            
        self.session_name = session_path.name
        self.imports = {"import requests", "import json", "from datetime import datetime"}
        self.helper_functions = set()
        
        code_parts = []
        
        # 生成头部注释
        code_parts.append(self._generate_header_comment(records))
        
        # 生成会话类
        code_parts.append(self._generate_session_class(records))
        
        # 生成主函数
        code_parts.append(self._generate_main_function(records))
        
        # 组装最终代码
        final_code = "\n".join([
            "\n".join(sorted(self.imports)),
            "",
            "\n".join(self.helper_functions),
            "",
            *code_parts
        ])
        
        return final_code
    
    async def generate_session_code_async(self, records: List[RequestRecord], session_path: Path) -> str:
        """异步生成整个会话的Python代码"""
        if not records:
            return "# 没有找到HTTP请求记录\nprint('No requests found')\n"
            
        self.session_name = session_path.name
        self.imports = {"import requests", "import json", "from datetime import datetime"}
        self.helper_functions = set()
        
        # 使用线程池并发处理请求方法生成
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=4) as executor:
            # 并发生成所有请求方法
            tasks = []
            for i, record in enumerate(records):
                if record.resource_type in ['xhr', 'fetch']:  # 只转换API请求
                    task = loop.run_in_executor(
                        executor, 
                        self._generate_request_method, 
                        record, i
                    )
                    tasks.append(task)
            
            method_codes = await asyncio.gather(*tasks)
        
        # 组装代码
        code_parts = []
        code_parts.append(self._generate_header_comment(records))
        
        # 构建会话类
        class_code = [
            "class WebSession:",
            '    """Web会话类，包含录制的所有HTTP请求"""',
            "    ",
            "    def __init__(self):",
            "        self.session = requests.Session()",
            "        self.base_headers = {}",
            "        self.results = []",
            "        ",
        ]
        
        # 添加生成的方法
        for method_code in method_codes:
            if method_code:
                class_code.extend(method_code)
                class_code.append("")
        
        # 添加执行所有请求的方法
        api_count = len([r for r in records if r.resource_type in ['xhr', 'fetch']])
        class_code.extend([
            "    def run_all_requests(self):",
            '    """执行所有录制的请求"""',
            f"        print(f'开始执行 {api_count} 个API请求...')",
            "        ",
            "        for method_name in self._get_request_methods():",
            "            try:",
            "                print(f'执行: {method_name}')",
            "                method = getattr(self, method_name)",
            "                result = method()",
            "                self.results.append({'method': method_name, 'result': result, 'success': True})",
            "            except Exception as e:",
            "                print(f'[FAIL] {method_name} 执行失败: {e}')",
            "                self.results.append({'method': method_name, 'error': str(e), 'success': False})",
            "        ",
            "        return self.results",
            "    ",
            "    def _get_request_methods(self):",
            '    """获取所有请求方法名"""',
            f"        return {[f'request_{i}' for i, r in enumerate(records) if r.resource_type in ['xhr', 'fetch']]}",
        ])
        
        code_parts.append("\n".join(class_code))
        code_parts.append(self._generate_main_function(records))
        
        # 组装最终代码
        final_code = "\n".join([
            "\n".join(sorted(self.imports)),
            "",
            "\n".join(self.helper_functions),
            "",
            *code_parts
        ])
        
        return final_code
    
    def _generate_header_comment(self, records: List[RequestRecord]) -> str:
        """生成头部注释"""
        api_count = len([r for r in records if r.resource_type in ['xhr', 'fetch']])
        domains = set()
        for r in records:
            try:
                domains.add(urlparse(r.url).netloc)
            except:
                pass
                
        return f'''"""
Generated from Web Analyzer Session: {self.session_name}
生成时间: {{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}

会话统计:
- 总请求数: {len(records)}
- API请求数: {api_count}
- 涉及域名: {', '.join(sorted(domains))}

此代码可直接运行，用于AI分析时验证请求逻辑
"""'''
    
    def _generate_session_class(self, records: List[RequestRecord]) -> str:
        """生成会话类，包含所有请求方法"""
        class_code = [
            "class WebSession:",
            "    \"\"\"Web会话类，包含录制的所有HTTP请求\"\"\"",
            "    ",
            "    def __init__(self):",
            "        self.session = requests.Session()",
            "        self.base_headers = {}",
            "        self.results = []",
            "        ",
        ]
        
        # 为每个请求生成方法
        for i, record in enumerate(records):
            if record.resource_type in ['xhr', 'fetch']:  # 只转换API请求
                method_code = self._generate_request_method(record, i)
                class_code.extend(method_code)
                class_code.append("")
        
        # 生成执行所有请求的方法
        class_code.extend([
            "    def run_all_requests(self):",
            "        \"\"\"执行所有录制的请求\"\"\"",
            "        print(f'开始执行 {len([r for r in self._get_request_methods()])} 个API请求...')",
            "        ",
            "        for method_name in self._get_request_methods():",
            "            try:",
            "                print(f'执行: {method_name}')",
            "                method = getattr(self, method_name)",
            "                result = method()",
            "                self.results.append({'method': method_name, 'result': result, 'success': True})",
            "            except Exception as e:",
            "                print(f'[FAIL] {method_name} 执行失败: {e}')",
            "                self.results.append({'method': method_name, 'error': str(e), 'success': False})",
            "        ",
            "        return self.results",
            "    ",
            "    def _get_request_methods(self):",
            "        \"\"\"获取所有请求方法名\"\"\"",
            f"        return {[f'request_{i}' for i, r in enumerate(records) if r.resource_type in ['xhr', 'fetch']]}",
        ])
        
        return "\n".join(class_code)
    
    def _generate_request_method(self, record: RequestRecord, index: int) -> List[str]:
        """为单个请求生成Python方法"""
        method_lines = []
        
        # 方法签名和文档
        url_info = self._extract_url_info(record.url)
        method_lines.extend([
            f"    def request_{index}(self):",
            f"        \"\"\"",
            f"        {(record.method or 'GET').upper()} {url_info['path']}",
            f"        域名: {url_info['domain']}",
            f"        状态: {record.status or 'Unknown'}",
        ])
        
        if record.call_stack:
            method_lines.append(f"        调用栈: {record.call_stack.split()[0] if record.call_stack else 'Unknown'}")
        
        method_lines.extend([
            f"        \"\"\"",
            f"        # 请求配置",
            f"        method = {json.dumps((record.method or 'GET').upper(), ensure_ascii=False)}",
            f"        url = {json.dumps(record.url or '', ensure_ascii=False)}",
        ])
        
        # 处理请求头
        if record.headers:
            headers_code = self._generate_headers_code(record.headers)
            method_lines.append(f"        headers = {headers_code}")
        
        # 处理请求体
        data_code = ""
        if record.post_data and (record.method or "").upper() in ['POST', 'PUT', 'PATCH']:
            data_code = self._generate_data_code(record.post_data)
        
        # 生成请求调用
        request_params = ["method=method", "url=url"]
        if record.headers:
            request_params.append("headers=headers")
        if data_code:
            method_lines.append(f"        {data_code}")
            if "json_data" in data_code:
                request_params.append("json=json_data")
            else:
                request_params.append("data=data")
        
        method_lines.extend([
            f"        ",
            f"        # 发送请求",
            f"        response = self.session.request({', '.join(request_params)})",
            f"        ",
            f"        # 处理响应",
            f"        result = {{",
            f"            'url': url,",
            f"            'method': method,",
            f"            'status_code': response.status_code,",
            f"            'headers': dict(response.headers),",
            f"        }}",
            f"        ",
            f"        # 尝试解析JSON响应",
            f"        try:",
            f"            result['json'] = response.json()",
            f"        except:",
            f"            result['text'] = response.text[:500]  # 限制响应文本长度",
            f"        ",
            f"        print(f'[OK] {{result[\"method\"]}} {{result[\"url\"]}} -> {{result[\"status_code\"]}}')",
            f"        return result",
        ])
        
        return method_lines
    
    def _generate_headers_code(self, headers: Dict[str, str]) -> str:
        """生成请求头代码"""
        # 过滤掉一些自动生成的头
        filtered_headers = {}
        skip_headers = {
            'host', 'connection', 'content-length', 'accept-encoding',
            'cache-control', 'pragma', 'sec-fetch-dest', 'sec-fetch-mode', 
            'sec-fetch-site', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'
        }
        
        for key, value in headers.items():
            if key.lower() not in skip_headers:
                filtered_headers[key] = value
        
        return json.dumps(filtered_headers, ensure_ascii=False)
    
    def _generate_data_code(self, post_data: str) -> str:
        """生成请求体代码"""
        if not post_data:
            return ""
        
        # 尝试解析为JSON
        try:
            json.loads(post_data)
            return f"json_data = json.loads({json.dumps(post_data, ensure_ascii=False)})"
        except:
            # 检查是否为表单数据
            if '=' in post_data and '&' in post_data:
                # URL编码的表单数据
                return f"data = {json.dumps(post_data, ensure_ascii=False)}"
            else:
                # 其他类型的数据
                return f"data = {json.dumps(post_data, ensure_ascii=False)}"
    
    def _extract_url_info(self, url: str) -> Dict[str, str]:
        """提取URL信息"""
        try:
            parsed = urlparse(url)
            return {
                'domain': parsed.netloc,
                'path': parsed.path or '/',
                'query': parsed.query,
                'scheme': parsed.scheme
            }
        except:
            return {
                'domain': 'unknown',
                'path': url,
                'query': '',
                'scheme': 'http'
            }

    def _generate_main_function(self, records: List[RequestRecord]) -> str:
        """生成主函数"""
        return '''
if __name__ == "__main__":
    print("[INFO] 开始执行Web会话请求...")
    
    # 创建会话实例
    session = WebSession()
    
    # 执行所有请求
    results = session.run_all_requests()
    
    # 输出统计
    success_count = len([r for r in results if r.get('success')])
    total_count = len(results)
    
    print(f"\\n[STAT] 执行完成:")
    print(f"  - 总请求数: {total_count}")
    print(f"  - 成功: {success_count}")
    print(f"  - 失败: {total_count - success_count}")
    
    # 保存结果到文件
    with open(f'session_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print("\\n[OK] 结果已保存到 session_results_*.json")
'''


def _safe_script_stem(method: str, url: str, index: int) -> str:
    try:
        parsed = urlparse(url)
        path = (parsed.path or "/").strip("/")
        if not path:
            path = "root"
        path = re.sub(r"[^a-zA-Z0-9_\-]+", "_", path)
        path = path[:60].strip("_") or "req"
        domain = re.sub(r"[^a-zA-Z0-9_\-]+", "_", parsed.netloc or "domain")[:40]
        base = f"{index:04d}_{method.lower()}_{domain}_{path}"
        base = base.strip("_")
        if not base:
            base = f"{index:04d}_{method.lower()}"
        return base
    except Exception:
        return f"{index:04d}_{method.lower()}"


def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    skip = {
        "host",
        "connection",
        "content-length",
        "accept-encoding",
    }
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k.lower() in skip:
            continue
        out[k] = v
    return out


def _py_literal(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def generate_single_request_python_code(record: RequestRecord, session_path: Path, index: int) -> str:
    method = (record.method or "GET").upper()
    url = record.url or ""
    headers = _filter_headers(dict(record.headers or {}))

    post_data = record.post_data
    body_block = ""
    send_args = ["method=method", "url=url"]
    if headers:
        body_block += f"    headers = {_py_literal(headers)}\n"
        send_args.append("headers=headers")

    json_obj = None
    if post_data and method in {"POST", "PUT", "PATCH"}:
        try:
            json_obj = json.loads(post_data)
        except Exception:
            json_obj = None

    if post_data and method in {"POST", "PUT", "PATCH"}:
        if json_obj is not None:
            body_block += f"    json_data = json.loads({_py_literal(post_data)})\n"
            send_args.append("json=json_data")
        else:
            body_block += f"    data = {_py_literal(post_data)}\n"
            send_args.append("data=data")

    storage_state_rel = "browser_data/storage/storage_state.json"
    storage_state_legacy_rel = "browser_data/storage_state.json"

    code = "".join(
        [
            "import json\n",
            "from pathlib import Path\n",
            "import requests\n",
            "\n",
            "\n",
            "def _apply_storage_state(sess: requests.Session, storage_state_path: Path) -> None:\n",
            "    try:\n",
            "        if not storage_state_path.exists():\n",
            "            return\n",
            "        data = json.loads(storage_state_path.read_text(encoding='utf-8'))\n",
            "        cookies = data.get('cookies') or []\n",
            "        for c in cookies:\n",
            "            try:\n",
            "                sess.cookies.set(\n",
            "                    c.get('name'),\n",
            "                    c.get('value'),\n",
            "                    domain=c.get('domain'),\n",
            "                    path=c.get('path') or '/',\n",
            "                )\n",
            "            except Exception:\n",
            "                continue\n",
            "    except Exception:\n",
            "        return\n",
            "\n",
            "\n",
            "def run() -> dict:\n",
            "    sess = requests.Session()\n",
            f"    p = Path(__file__).resolve().parents[1] / '{storage_state_rel}'\n",
            f"    if not p.exists():\n",
            f"        p = Path(__file__).resolve().parents[1] / '{storage_state_legacy_rel}'\n",
            "    _apply_storage_state(sess, p)\n",
            f"    method = '{method}'\n",
            f"    url = {_py_literal(url)}\n",
            body_block,
            f"    resp = sess.request({', '.join(send_args)})\n",
            "    out = {\n",
            "        'method': method,\n",
            "        'url': url,\n",
            "        'status_code': resp.status_code,\n",
            "        'headers': dict(resp.headers),\n",
            "    }\n",
            "    try:\n",
            "        out['json'] = resp.json()\n",
            "    except Exception:\n",
            "        out['text'] = resp.text[:2000]\n",
            "    return out\n",
            "\n",
            "\n",
            "if __name__ == '__main__':\n",
            "    result = run()\n",
            "    print(f\"{result['status_code']} {result['method']} {result['url']}\")\n",
            "    if 'json' in result:\n",
            "        print(json.dumps(result['json'], ensure_ascii=False, indent=2)[:4000])\n",
            "    else:\n",
            "        print((result.get('text') or '')[:4000])\n",
        ]
    )
    return code


def generate_single_request_js_code(record: RequestRecord, index: int) -> str:
    method = (record.method or "GET").upper()
    url = record.url or ""
    headers = _filter_headers(dict(record.headers or {}))

    body = None
    if record.post_data and method in {"POST", "PUT", "PATCH"}:
        body = record.post_data

    headers_js = json.dumps(headers or {}, ensure_ascii=False, indent=2)
    body_js = json.dumps(body, ensure_ascii=False) if body is not None else "null"

    return "".join(
        [
            "const fs = require('fs');\n",
            "const path = require('path');\n",
            "\n",
            "function loadStorageStateCookies(urlStr) {\n",
            "  try {\n",
            "    const u = new URL(urlStr);\n",
            "    const sessionRoot = path.resolve(__dirname, '..');\n",
            "    const p1 = path.join(sessionRoot, 'browser_data', 'storage', 'storage_state.json');\n",
            "    const p2 = path.join(sessionRoot, 'browser_data', 'storage_state.json');\n",
            "    const p = fs.existsSync(p1) ? p1 : p2;\n",
            "    if (!fs.existsSync(p)) return [];\n",
            "    const data = JSON.parse(fs.readFileSync(p, 'utf-8'));\n",
            "    const cookies = data.cookies || [];\n",
            "    const host = (u.hostname || '').toLowerCase();\n",
            "    return cookies.filter(c => {\n",
            "      const d = String(c.domain || '').replace(/^\./, '').toLowerCase();\n",
            "      if (!d) return false;\n",
            "      return host === d || host.endsWith('.' + d);\n",
            "    });\n",
            "  } catch {\n",
            "    return [];\n",
            "  }\n",
            "}\n",
            "\n",
            "async function run() {\n",
            f"  const method = '{method}';\n",
            f"  const url = {json.dumps(url, ensure_ascii=False)};\n",
            f"  const headers = {headers_js};\n",
            f"  const body = {body_js};\n",
            "\n",
            "  const cookies = loadStorageStateCookies(url);\n",
            "  if (cookies.length) {\n",
            "    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');\n",
            "    headers['cookie'] = headers['cookie'] || headers['Cookie'] || cookieHeader;\n",
            "  }\n",
            "\n",
            "  const options = { method, headers: headers || undefined };\n",
            "  if (body !== null) { options.body = body; }\n",
            "\n",
            "  const res = await fetch(url, options);\n",
            "  const text = await res.text();\n",
            "  let out;\n",
            "  try { out = JSON.parse(text); } catch { out = text; }\n",
            "  console.log(res.status, method, url);\n",
            "  if (typeof out === 'object') {\n",
            "    console.log(JSON.stringify(out, null, 2).slice(0, 4000));\n",
            "  } else {\n",
            "    console.log(String(out).slice(0, 4000));\n",
            "  }\n",
            "  return { status: res.status, method, url, out };\n",
            "}\n",
            "\n",
            "run().catch(err => {\n",
            "  console.error('request failed', err);\n",
            "  process.exit(1);\n",
            "});\n",
        ]
    )


def generate_per_request_scripts(session_path: Path, *, only_resource_types: Optional[List[str]] = None) -> Dict[str, Any]:
    requests_file = session_path / "requests.json"
    if not requests_file.exists():
        return {"success": False, "message": "requests.json not found", "generated": 0}

    data = json.loads(requests_file.read_text(encoding="utf-8"))
    records = [RequestRecord.from_dict(item) for item in data]

    if only_resource_types is None:
        only_set = set()
    else:
        only_set = set(only_resource_types)

    out_py = session_path / "requests_py"
    out_js = session_path / "requests_js"
    out_py.mkdir(parents=True, exist_ok=True)
    out_js.mkdir(parents=True, exist_ok=True)

    generated_py = 0
    generated_js = 0
    skipped = 0

    index_items: List[Dict[str, Any]] = []

    for i, r in enumerate(records):
        rt = (r.resource_type or "").lower()
        if only_set and rt not in only_set:
            skipped += 1
            continue

        method = (r.method or "GET").upper()
        url = r.url or ""
        stem = _safe_script_stem(method, url, i)
        sig = hashlib.md5((method + "|" + url).encode("utf-8", errors="ignore")).hexdigest()[:8]
        stem = f"{stem}_{sig}"

        py_path = out_py / f"{stem}.py"
        js_path = out_js / f"{stem}.js"

        py_code = generate_single_request_python_code(r, session_path, i)
        py_path.write_text(py_code, encoding="utf-8")
        generated_py += 1

        js_code = generate_single_request_js_code(r, i)
        js_path.write_text(js_code, encoding="utf-8")
        generated_js += 1

        index_items.append(
            {
                "index": i,
                "id": r.id,
                "resource_type": r.resource_type,
                "method": method,
                "url": url,
                "status": r.status,
                "call_stack": r.call_stack,
                "py": str(py_path.relative_to(session_path)),
                "js": str(js_path.relative_to(session_path)),
            }
        )

    (session_path / "requests_index.json").write_text(
        json.dumps(index_items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "success": True,
        "message": "ok",
        "generated_py": generated_py,
        "generated_js": generated_js,
        "skipped": skipped,
        "only_resource_types": sorted(list(only_set)),
        "index_file": "requests_index.json",
        "py_dir": "requests_py",
        "js_dir": "requests_js",
    }


def generate_code_from_session(session_path: Path) -> str:
    """从会话目录生成Python代码"""
    generator = PythonCodeGenerator()
    
    # 读取请求记录
    requests_file = session_path / "requests.json"
    if not requests_file.exists():
        return "# 未找到requests.json文件\nprint('No requests.json found')\n"
    
    try:
        with open(requests_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        records = [RequestRecord.from_dict(item) for item in data]
        # 生成基础代码
        base_code = generator.generate_session_code(records, session_path)
        
        # 提取所有call_stack信息用于JavaScript分析
        call_stacks = [record.call_stack for record in records if record.call_stack]
        
        # 增强代码，添加JavaScript分析功能
        if call_stacks:
            enhanced_code = enhance_code_with_js_analysis(base_code, call_stacks, session_path)
            try:
                compile(enhanced_code, str(session_path / "replay_session.py"), "exec")
                return enhanced_code
            except SyntaxError:
                try:
                    compile(base_code, str(session_path / "replay_session.py"), "exec")
                    return base_code
                except SyntaxError as e:
                    msg = f"Generated code is not runnable: {repr(e)}"
                    return "import sys\n" + f"print({json.dumps(msg, ensure_ascii=False)})\n" + "sys.exit(1)\n"
        else:
            try:
                compile(base_code, str(session_path / "replay_session.py"), "exec")
            except SyntaxError as e:
                msg = f"Generated code is not runnable: {repr(e)}"
                return "import sys\n" + f"print({json.dumps(msg, ensure_ascii=False)})\n" + "sys.exit(1)\n"
            return base_code
         
    except Exception as e:
        return f"# 读取请求记录时出错: {e}\nprint('Error reading requests: {e}')\n"


def _format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(value)
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def generate_session_summary_markdown(session_path: Path, *, max_examples: int = 30) -> str:
    requests_file = session_path / "requests.json"
    data: List[Dict[str, Any]] = []
    if requests_file.exists():
        try:
            data = json.loads(requests_file.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                data = []
        except Exception:
            data = []

    metadata_file = session_path / "metadata.json"
    metadata: Dict[str, Any] = {}
    if metadata_file.exists():
        try:
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                metadata = {}
        except Exception:
            metadata = {}

    total_requests = len(data)
    api_requests = [r for r in data if str(r.get("resource_type", "")).lower() in {"xhr", "fetch"}]

    domains = Counter()
    methods = Counter()
    resource_types = Counter()
    status_codes = Counter()
    api_endpoints = Counter()

    for r in data:
        url = str(r.get("url", ""))
        method = str(r.get("method", "GET")).upper()
        rt = str(r.get("resource_type", ""))
        st = r.get("status") if r.get("status") is not None else r.get("status_code")

        methods[method] += 1
        if rt:
            resource_types[rt] += 1
        if st is not None:
            status_codes[str(st)] += 1

        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains[parsed.netloc] += 1
            if str(rt).lower() in {"xhr", "fetch"}:
                api_endpoints[f"{method} {parsed.path or '/'}"] += 1
        except Exception:
            pass

    def _sample_request_for_doc(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not rows:
            return {}
        if isinstance(rows[0], dict):
            return rows[0]
        return {}

    def _dir_file_count(p: Path) -> int:
        try:
            if not p.exists() or not p.is_dir():
                return 0
            return len([x for x in p.iterdir() if x.is_file()])
        except Exception:
            return 0

    def _read_text_head(p: Path, limit: int = 50_000) -> str:
        try:
            if not p.exists() or not p.is_file():
                return ""
            return p.read_text(encoding="utf-8", errors="ignore")[:limit]
        except Exception:
            return ""

    def _count_lines(text: str) -> int:
        if not text:
            return 0
        return text.count("\n") + 1

    expected_tree = [
        ("requests.json", "录制的请求列表（核心数据）"),
        ("metadata.json", "会话元信息（统计/时长/域名等）"),
        ("trace.har", "HAR 文件（可用于抓包工具复现）"),
        ("replay_session.py", "回放/验证用 Python 脚本（按录制生成）"),
        ("requests_index.json", "逐请求脚本索引（py/js 文件映射）"),
        ("requests_py/", "逐请求 Python 脚本目录"),
        ("requests_js/", "逐请求 JS(fetch) 脚本目录"),
        ("responses/", "响应体落盘（response_body_path 指向这里）"),
        ("hooks/", "Hook 控制台日志（调用栈/事件）"),
        ("scripts/", "页面脚本资源（尽量抓取并格式化）"),
        ("styles/", "样式资源"),
        ("images/", "图片资源"),
        ("browser_data/", "浏览器侧数据快照（storage/performance/dom 等）"),
        ("screenshots/", "截图（可选）"),
    ]

    existing = []
    for rel, desc in expected_tree:
        p = session_path / rel.rstrip("/")
        ok = p.exists()
        extra = ""
        try:
            if ok and p.is_file():
                extra = f" ({_format_bytes(p.stat().st_size)})"
        except Exception:
            extra = ""
        existing.append(f"- [{'x' if ok else ' '}] `{rel}`{extra} - {desc}")

    api_examples = "\n".join([f"- `{k}` ({v})" for k, v in api_endpoints.most_common(max_examples)])
    if not api_examples:
        api_examples = "- (无)"

    def _counter_md(counter: Counter, *, top: int = 20) -> str:
        items = counter.most_common(top)
        if not items:
            return "- (无)"
        return "\n".join([f"- `{k}`: {v}" for k, v in items])

    lines = [
        f"# Session Summary - {session_path.name}",
        "",
        f"生成时间: {datetime.now().isoformat()}",
        "",
        "## 0) Quick Start (for AI)",
        "目标: 给 AI 足够上下文, 使其可以直接定位代码、复现问题、提出修复并给出验证方式。",
        "",
        "你可以优先阅读:",
        "- 1) 会话产物（文件结构）: 这次录制落盘了哪些数据",
        "- 2) 请求概览: 关键域名/端点/状态码",
        "- 6) requests.json 结构: 字段含义与样例",
        "- 7) 复现与验证步骤: 如何在本项目里重跑/验证",
        "",
        "## 0.1) 会话元信息 (metadata.json)",
        f"- start_url: {metadata.get('start_url') if metadata else '(无)'}",
        f"- start_time: {metadata.get('start_time') if metadata else '(无)'}",
        f"- end_time: {metadata.get('end_time') if metadata else '(无)'}",
        f"- duration_seconds: {metadata.get('duration_seconds') if metadata else '(无)'}",
        f"- requests_with_call_stack: {metadata.get('requests_with_call_stack') if metadata else '(无)'}",
        "",
        "## 1) 会话产物（文件结构）",
        "\n".join(existing),
        "",
        "### 文件/目录数量概览",
        f"- responses/: {_dir_file_count(session_path / 'responses')} files",
        f"- scripts/: {_dir_file_count(session_path / 'scripts')} files",
        f"- styles/: {_dir_file_count(session_path / 'styles')} files",
        f"- images/: {_dir_file_count(session_path / 'images')} files",
        f"- hooks/console.log: {_count_lines(_read_text_head(session_path / 'hooks' / 'console.log'))} lines",
        "",
        "## 2) 请求概览",
        f"- 总请求数: {total_requests}",
        f"- API 请求数(xhr/fetch): {len(api_requests)}",
        "",
        "### 域名统计(Top)",
        _counter_md(domains),
        "",
        "### 方法统计",
        _counter_md(methods),
        "",
        "### 资源类型统计",
        _counter_md(resource_types),
        "",
        "### 状态码统计",
        _counter_md(status_codes),
        "",
        "### API 端点示例(Top)",
        api_examples,
        "",
        "## 3) 关键模块职责（定位代码时优先看这些）",
        "- `backend/app/services/recorder_service.py`: 会话管理、分页查询、清空/删除、落盘与导出触发",
        "- `backend/core/network_recorder.py`: Playwright 监听 request/response/console，生成 RequestRecord",
        "- `backend/core/resource_archiver.py`: 创建会话目录并落盘 requests/metadata/har/响应体/browser_data",
        "- `backend/core/code_generator.py`: 从 requests.json 生成回放代码与逐请求脚本",
        "- `backend/app/api/v1/crawler.py`: 爬虫/会话 API（start/stop/list/requests/export/zip）",
        "- `frontend/src/pages/Crawler/index.tsx`: 网络控制台 UI（分页/搜索/清空/详情抽屉）",
        "",
        "## 4) 常用 API（前端通常调用这些）",
        "- `GET /api/v1/crawler/sessions`: 会话列表",
        "- `GET /api/v1/crawler/requests/{session_id}`: 会话请求分页(支持 q/resource_type/method/status)",
        "- `DELETE /api/v1/crawler/requests/{session_id}`: 清空会话请求",
        "- `POST /api/v1/crawler/start`: 启动录制",
        "- `POST /api/v1/crawler/stop/{session_id}`: 停止录制(会落盘并生成回放脚本)",
        "- `GET /api/v1/crawler/download-zip/{session_id}`: 下载会话目录 zip",
        "- `POST /api/v1/code-generator/generate`: 为会话目录生成代码（同时生成本 summary）",
        "",
        "## 5) 数据流（快速理解录制→落盘→生成代码）",
        "1. 前端调用 start -> `RecorderService.start_recording`",
        "2. Playwright 事件在 `NetworkRecorder` 中被捕获为 `RequestRecord`，响应体落盘到 `responses/`",
        "3. stop -> `ResourceArchiver.save_requests/save_metadata/save_har` 生成 `requests.json/metadata.json/trace.har`",
        "4. `core/code_generator.py` 读取 `requests.json` 生成 `replay_session.py` 与 `requests_py/requests_js/requests_index.json`",
        "",
        "## 6) requests.json 结构 (AI 必读)",
        "requests.json 是一个数组, 每一项对应一个 RequestRecord。常用字段:",
        "- `id`: 请求唯一标识(与响应体文件名相关)",
        "- `timestamp`: 请求发起时间戳(秒)",
        "- `method` / `url` / `headers` / `post_data`: 请求信息",
        "- `status` / `response_headers` / `response_body_path` / `response_size`: 响应信息",
        "- `content_type`: 响应 Content-Type(不含 charset)",
        "- `call_stack`: JS 调用栈(重要, 用于定位签名/加密逻辑来源)",
        "- `resource_type`: xhr/fetch/script/stylesheet/image/document 等",
        "",
        "示例(第一条记录):",
        "```json",
        json.dumps(_sample_request_for_doc(data), ensure_ascii=False, indent=2) if data else "{}",
        "```",
        "",
        "定位响应体: 如果记录包含 `response_body_path`, 该路径相对当前 session 目录。",
        "例如: `responses/123.json` 表示 `./responses/123.json`。",
        "",
        "## 7) 复现与验证步骤 (推荐给 AI 的操作顺序)",
        "1. 获取会话列表: `GET /api/v1/crawler/sessions`",
        "2. 拉取请求分页: `GET /api/v1/crawler/requests/{session_id}?offset=0&limit=30&q=...`",
        "3. 若需要清空: `DELETE /api/v1/crawler/requests/{session_id}`",
        "4. 结束录制后生成回放脚本: `POST /api/v1/crawler/stop/{session_id}` (会写入 session 目录)",
        "5. 生成代码与总结: `POST /api/v1/code-generator/generate`",
        "6. 本地验证回放脚本: 运行 `replay_session.py` (或生成的 session_*.py) 并对比状态码/返回结构",
        "",
        "## 8) 常见问题与排查清单",
        "- 请求列表为空: 检查 `requests.json` 是否存在; 检查录制是否已 stop 并落盘; 检查前端分页 offset/limit",
        "- 清空不生效: 检查是否调用了 `DELETE /api/v1/crawler/requests/{session_id}`; 检查 session 级 requests.json 是否被写空",
        "- JS 调用栈缺失: 可能是 Hook 注入失败或该请求不是 fetch/xhr; 检查 `hooks/console.log`",
        "- 响应体缺失: `response_body_path` 为空或落盘失败; 检查 `responses/` 与 `scripts/` 目录",
        "",
        "## 9) AI 处理模板 (建议按此输出)",
        "- Problem: 用一句话描述要解决的问题",
        "- Expected Behavior: 期望行为是什么",
        "- Observed Behavior: 实际行为是什么(尽量引用本 summary 的统计/样例)",
        "- Root Cause Hypothesis: 1-3 条假设, 每条对应到具体文件/函数",
        "- Change Plan: 要改哪些文件/函数, 为什么",
        "- Patch Summary: 关键改动点(接口/字段/逻辑)",
        "- Verification: 如何验证(包含 API 调用或脚本运行)",
    ]
    return "\n".join(lines) + "\n"


def write_session_summary(session_path: Path, *, filename: str = "SESSION_SUMMARY.md") -> Path:
    out_path = session_path / filename
    content = generate_session_summary_markdown(session_path)
    out_path.write_text(content, encoding="utf-8")
    return out_path
