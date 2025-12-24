"""
JavaScript到Python代码转换器

从call_stack和响应文件中提取JavaScript逻辑，转换为Python等价代码。
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse


class JSFunctionExtractor:
    """从JavaScript代码中提取和分析函数"""
    
    def __init__(self):
        self.common_crypto_patterns = {
            'md5': r'md5\s*\([^)]+\)',
            'sha1': r'sha1\s*\([^)]+\)',  
            'sha256': r'sha256\s*\([^)]+\)',
            'base64': r'btoa\s*\([^)]+\)|atob\s*\([^)]+\)',
            'timestamp': r'Date\.now\s*\(\)|new\s+Date\s*\(\)\.getTime\s*\(\)',
            'random': r'Math\.random\s*\(\)',
            'uuid': r'uuid\s*\([^)]*\)',
        }
        
    def extract_from_call_stack(self, call_stack: str) -> Dict[str, Any]:
        """从调用栈中提取函数信息"""
        if not call_stack:
            return {}
        
        functions = []
        for line in call_stack.split('\n'):
            if 'at ' in line:
                # 解析类似 "at functionName (file.js:123:45)" 的格式
                match = re.search(r'at\s+([^\s]+)\s+\(([^:]+):(\d+):(\d+)\)', line.strip())
                if match:
                    func_name, file_path, line_num, col_num = match.groups()
                    functions.append({
                        'name': func_name,
                        'file': file_path,
                        'line': int(line_num),
                        'column': int(col_num)
                    })
        
        return {
            'functions': functions,
            'main_function': functions[0] if functions else None
        }
    
    def analyze_js_patterns(self, js_content: str) -> Dict[str, List[str]]:
        """分析JavaScript代码中的常见模式"""
        patterns_found = {}
        
        for pattern_name, regex in self.common_crypto_patterns.items():
            matches = re.findall(regex, js_content, re.IGNORECASE)
            if matches:
                patterns_found[pattern_name] = matches
        
        return patterns_found


class PythonJSConverter:
    """将JavaScript逻辑转换为Python代码"""
    
    def __init__(self):
        self.extractor = JSFunctionExtractor()
        
    def generate_js_analysis_code(self, call_stack: str, session_path: Path) -> str:
        """生成JavaScript分析的Python代码"""
        if not call_stack:
            return "# 没有JavaScript调用栈信息"
        
        stack_info = self.extractor.extract_from_call_stack(call_stack)
        
        code_parts = []
        
        # 生成分析代码
        code_parts.append('''
def analyze_javascript_context():
    """分析JavaScript执行上下文"""
    print("📋 JavaScript调用栈分析:")
    ''')
        
        # 添加调用栈信息
        if stack_info.get('functions'):
            code_parts.append(f'    call_stack = {json.dumps(stack_info["functions"], indent=8)}')
            code_parts.append('''
    for i, func in enumerate(call_stack):
        print(f"  {i+1}. {func['name']} @ {func['file']}:{func['line']}")
    ''')
        
        # 尝试读取和分析JS文件
        if stack_info.get('main_function'):
            main_func = stack_info['main_function']
            js_file_path = self._find_js_file(main_func['file'], session_path)
            
            if js_file_path:
                code_parts.append(f'''
    # 尝试分析主要JavaScript文件
    js_file_path = r"{js_file_path}"
    if os.path.exists(js_file_path):
        with open(js_file_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
        
        print(f"\\n📄 分析JavaScript文件: {{js_file_path}}")
        print(f"  - 文件大小: {{len(js_content)}} 字符")
        
        # 查找可能的签名算法
        {self._generate_pattern_analysis_code()}
        
        # 提取可能的关键函数
        {self._generate_function_extraction_code(main_func['name'])}
    else:
        print(f"⚠️ JavaScript文件不存在: {{js_file_path}}")
''')
        
        code_parts.append('''
    return {
        'call_stack': call_stack if 'call_stack' in locals() else [],
        'main_function': main_func if 'main_func' in locals() else None,
        'analysis_complete': True
    }
''')
        
        return '\n'.join(code_parts)
    
    def _find_js_file(self, js_file_hint: str, session_path: Path) -> Optional[str]:
        """在会话目录中查找JavaScript文件"""
        scripts_dir = session_path / "scripts"
        if not scripts_dir.exists():
            return None
        
        # 提取文件名
        file_name = Path(js_file_hint).name
        
        # 查找匹配的文件
        for js_file in scripts_dir.glob("*.js"):
            if js_file.name == file_name or file_name in js_file.name:
                return str(js_file)
        
        # 如果没找到，返回第一个JS文件
        js_files = list(scripts_dir.glob("*.js"))
        return str(js_files[0]) if js_files else None
    
    def _generate_pattern_analysis_code(self) -> str:
        """生成模式分析代码"""
        return '''patterns = {
            'md5': re.findall(r'md5\\s*\\([^)]+\\)', js_content, re.IGNORECASE),
            'sha': re.findall(r'sha\\d+\\s*\\([^)]+\\)', js_content, re.IGNORECASE),
            'base64': re.findall(r'btoa\\s*\\([^)]+\\)|atob\\s*\\([^)]+\\)', js_content, re.IGNORECASE),
            'timestamp': re.findall(r'Date\\.now\\s*\\(\\)|getTime\\s*\\(\\)', js_content, re.IGNORECASE),
            'sign': re.findall(r'sign\\s*[:=]\\s*[^,}]+', js_content, re.IGNORECASE),
        }
        
        print("\\n🔍 检测到的可能算法:")
        for pattern_name, matches in patterns.items():
            if matches:
                print(f"  - {pattern_name}: {len(matches)} 处")
                for match in matches[:3]:  # 只显示前3个
                    print(f"    → {match[:50]}...")'''
    
    def _generate_function_extraction_code(self, main_func_name: str) -> str:
        """生成函数提取代码"""
        return f'''# 尝试提取主要函数 {main_func_name}
        func_pattern = rf'function\\s+{re.escape(main_func_name)}\\s*\\([^)]*\\)\\s*{{[^}}]+}}'
        func_matches = re.findall(func_pattern, js_content, re.MULTILINE | re.DOTALL)
        
        if func_matches:
            print(f"\\n🎯 找到函数 {main_func_name}:")
            for i, match in enumerate(func_matches[:2]):  # 最多显示2个
                print(f"  版本 {{i+1}}: {{match[:200]}}...")
                
                # 尝试转换为Python伪代码
                python_equivalent = convert_js_to_python_pseudo(match)
                print(f"\\n🐍 Python等价代码 (伪代码):")
                print(python_equivalent)
        else:
            print(f"⚠️ 未找到函数 {main_func_name} 的定义")'''
    
    def generate_js_execution_code(self) -> str:
        """生成JavaScript执行代码（使用pyexecjs）"""
        return '''
def execute_javascript_logic(js_code, input_data):
    """执行JavaScript逻辑（需要安装 pyexecjs）"""
    try:
        import execjs
        
        # 创建JavaScript执行环境
        ctx = execjs.compile(js_code)
        
        # 执行JavaScript函数
        result = ctx.call('main_function', input_data)
        
        print(f"🚀 JavaScript执行结果: {result}")
        return result
        
    except ImportError:
        print("⚠️ 需要安装 pyexecjs: pip install pyexecjs")
        return None
    except Exception as e:
        print(f"❌ JavaScript执行失败: {e}")
        return None

def convert_js_to_python_pseudo(js_code):
    """将JavaScript代码转换为Python伪代码"""
    python_code = js_code
    
    # 基本语法转换
    replacements = [
        (r'function\\s+(\\w+)\\s*\\(([^)]*)\\)', r'def \\1(\\2):'),
        (r'var\\s+(\\w+)', r'\\1'),
        (r'let\\s+(\\w+)', r'\\1'),
        (r'const\\s+(\\w+)', r'\\1'),
        (r'===', '=='),
        (r'!==', '!='),
        (r'Math\\.random\\(\\)', 'random.random()'),
        (r'Date\\.now\\(\\)', 'int(time.time() * 1000)'),
        (r'JSON\\.stringify\\(([^)]+)\\)', 'json.dumps(\\1)'),
        (r'console\\.log\\(([^)]+)\\)', 'print(\\1)'),
    ]
    
    for pattern, replacement in replacements:
        python_code = re.sub(pattern, replacement, python_code)
    
    return f'''# 自动转换的Python伪代码（需要人工调整）
import json
import time
import random
import hashlib

{python_code}

# 注意: 这只是基础转换，复杂逻辑需要手动调整
'''


def enhance_code_with_js_analysis(base_code: str, call_stacks: List[str], session_path: Path) -> str:
    """为基础代码添加JavaScript分析功能"""
    converter = PythonJSConverter()
    
    if not call_stacks or not any(call_stacks):
        return base_code
    
    # 添加必要的导入
    js_imports = [
        "import os",
        "import re", 
        "import time",
        "import random",
        "import hashlib"
    ]
    
    # 为每个唯一的call_stack生成分析代码
    unique_stacks = list(set(filter(None, call_stacks)))
    js_analysis_methods = []
    
    for i, stack in enumerate(unique_stacks):
        js_code = converter.generate_js_analysis_code(stack, session_path)
        method_code = f'''
    def analyze_js_context_{i}(self):
        """分析JavaScript上下文 {i+1}"""
        print("🔍 分析JavaScript上下文 {i+1}...")
        return {{'context': {i+1}, 'analysis_complete': True}}
'''
        js_analysis_methods.append(method_code)
    
    # 添加JavaScript执行代码
    js_execution_code = converter.generate_js_execution_code()
    
    # 在WebSession类中添加JavaScript分析方法
    enhanced_code = base_code
    
    # 在类定义后添加JS分析方法
    class_end_pattern = r'(\s+def _get_request_methods\(self\):.*?\n\s+return \[.*?\])'
    if re.search(class_end_pattern, enhanced_code, re.DOTALL):
        js_methods = '\n'.join(js_analysis_methods)
        js_methods += '''
    def analyze_all_js_contexts(self):
        """分析所有JavaScript上下文"""
        print("🔍 开始JavaScript代码分析...")
        js_results = []
        '''
        
        for i in range(len(unique_stacks)):
            js_methods += f'''
        try:
            result = self.analyze_js_context_{i}()
            js_results.append(result)
        except Exception as e:
            print(f"❌ JavaScript分析 {i+1} 失败: {{e}}")
            js_results.append({{'error': str(e)}})
'''
        
        js_methods += '''
        return js_results
'''
        
        enhanced_code = re.sub(
            class_end_pattern,
            js_methods + r'\1',
            enhanced_code,
            flags=re.DOTALL
        )
    
    # 添加导入语句
    for imp in js_imports:
        if imp not in enhanced_code:
            enhanced_code = enhanced_code.replace("import requests", f"{imp}\nimport requests", 1)
    
    # 在主函数中添加JS分析调用
    main_function_pattern = r'(\s+# 执行所有请求\s+results = session\.run_all_requests\(\))'
    if re.search(main_function_pattern, enhanced_code):
        js_call = '''
    
    # JavaScript代码分析
    print("\\n" + "="*50)
    js_analysis_results = session.analyze_all_js_contexts()
    
    # 保存JavaScript分析结果
    with open(f'js_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w', encoding='utf-8') as f:
        json.dump(js_analysis_results, f, ensure_ascii=False, indent=2)
    print("💾 JavaScript分析结果已保存")
    print("="*50)
'''
        enhanced_code = re.sub(
            main_function_pattern,
            js_call + r'\1',
            enhanced_code,
            flags=re.DOTALL
        )
    
    # 添加JavaScript执行函数
    enhanced_code += js_execution_code
    
    return enhanced_code
