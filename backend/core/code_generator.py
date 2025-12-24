"""
HTTP请求到Python代码的转换器

将录制的RequestRecord转换为可直接执行的Python代码，用于AI分析时运行验证。
"""

import json
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from models.request_record import RequestRecord
from .js_converter_simple import enhance_code_with_js_analysis


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
            "                print(f'❌ {method_name} 执行失败: {e}')",
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
            f"        {record.method} {url_info['path']}",
            f"        域名: {url_info['domain']}",
            f"        状态: {record.status or 'Unknown'}",
        ])
        
        if record.call_stack:
            method_lines.append(f"        调用栈: {record.call_stack.split()[0] if record.call_stack else 'Unknown'}")
        
        method_lines.extend([
            f"        \"\"\"",
            f"        # 请求配置",
            f"        url = '{record.url}'",
        ])
        
        # 处理请求头
        if record.headers:
            headers_code = self._generate_headers_code(record.headers)
            method_lines.append(f"        headers = {headers_code}")
        
        # 处理请求体
        data_code = ""
        if record.post_data and record.method.upper() in ['POST', 'PUT', 'PATCH']:
            data_code = self._generate_data_code(record.post_data)
        
        # 生成请求调用
        request_params = ["url"]
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
            f"        response = self.session.{record.method.lower()}({', '.join(request_params)})",
            f"        ",
            f"        # 处理响应",
            f"        result = {{",
            f"            'url': url,",
            f"            'method': '{record.method}',",
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
            f"        print(f'✅ {{result[\"method\"]}} {{result[\"url\"]}} -> {{result[\"status_code\"]}}')",
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
        
        return json.dumps(filtered_headers, ensure_ascii=False, indent=12)[1:-1].replace('\n            ', '\n        ')
    
    def _generate_data_code(self, post_data: str) -> str:
        """生成请求体代码"""
        if not post_data:
            return ""
        
        # 尝试解析为JSON
        try:
            json_obj = json.loads(post_data)
            return f"json_data = {json.dumps(json_obj, ensure_ascii=False, indent=8)}"
        except:
            # 检查是否为表单数据
            if '=' in post_data and '&' in post_data:
                # URL编码的表单数据
                return f"data = '{post_data}'"
            else:
                # 其他类型的数据
                return f"data = '''{post_data}'''"
    
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
    print("🚀 开始执行Web会话请求...")
    
    # 创建会话实例
    session = WebSession()
    
    # 执行所有请求
    results = session.run_all_requests()
    
    # 输出统计
    success_count = len([r for r in results if r.get('success')])
    total_count = len(results)
    
    print(f"\n📊 执行完成:")
    print(f"  - 总请求数: {total_count}")
    print(f"  - 成功: {success_count}")
    print(f"  - 失败: {total_count - success_count}")
    
    # 保存结果到文件
    with open(f'session_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print("\n💾 结果已保存到 session_results_*.json")
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
            body_block += f"    json_data = {_py_literal(json_obj)}\n"
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
            return enhanced_code
        else:
            return base_code
        
    except Exception as e:
        return f"# 读取请求记录时出错: {e}\nprint('Error reading requests: {e}')\n"
