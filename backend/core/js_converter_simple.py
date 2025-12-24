"""
简化版JavaScript到Python代码转换器

临时简化版本，主要功能是为代码生成器提供基本的JavaScript分析功能。
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any


def enhance_code_with_js_analysis(base_code: str, call_stacks: List[str], session_path: Path) -> str:
    """为基础代码添加简化的JavaScript分析功能"""
    
    if not call_stacks or not any(call_stacks):
        return base_code
    
    # 添加JavaScript分析方法到WebSession类
    js_analysis_code = '''
    def analyze_javascript_contexts(self):
        """分析JavaScript调用栈信息"""
        print("[INFO] JavaScript代码分析:")
        
        call_stacks = ['''
    
    # 添加调用栈数据
    for i, stack in enumerate(call_stacks):
        if stack:
            escaped_stack = stack.replace('"', '\\"')[:200]
            js_analysis_code += f'''
            # 调用栈 {i+1}
            "{escaped_stack}...",'''
    
    js_analysis_code += '''
        ]
        
        for i, stack in enumerate(call_stacks):
            if stack:
                print(f"  [INFO] 调用栈 {i+1}:")
                for line in stack.split('\\n')[:3]:  # 只显示前3行
                    if line.strip():
                        print(f"    → {line.strip()}")
        
        # 查找可能的JavaScript文件
        scripts_dir = Path(r"''' + str(session_path / "scripts") + '''")
        if scripts_dir.exists():
            js_files = list(scripts_dir.glob("*.js"))
            print(f"\\n[INFO] 发现 {len(js_files)} 个JavaScript文件:")
            for js_file in js_files:
                print(f"  - {js_file.name} ({js_file.stat().st_size} bytes)")
        
        return {
            'call_stacks_count': len([s for s in call_stacks if s]),
            'scripts_found': len(js_files) if 'js_files' in locals() else 0,
            'analysis_complete': True
        }
'''
    
    # 在类定义中查找合适位置插入JavaScript分析方法
    class_pattern = r'(\s+def _get_request_methods\(self\):.*?\n\s+return \[.*?\])'
    match = re.search(class_pattern, base_code, re.DOTALL)
    
    if match:
        # 在_get_request_methods方法前插入JavaScript分析方法
        enhanced_code = base_code.replace(match.group(0), js_analysis_code + match.group(0))
        
        # 在主函数中添加JavaScript分析调用
        main_pattern = r'(\s+# 执行所有请求\s+results = session\.run_all_requests\(\))'
        if re.search(main_pattern, enhanced_code):
            js_call = '''
    
    # JavaScript代码分析
    print("\\n" + "="*50)
    js_analysis = session.analyze_javascript_contexts()
    print("="*50)
'''
            enhanced_code = re.sub(main_pattern, js_call + r'\1', enhanced_code, flags=re.DOTALL)
        
        return enhanced_code
    
    return base_code


def extract_js_function_info(call_stack: str) -> Dict[str, Any]:
    """从调用栈中提取JavaScript函数信息"""
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


def find_js_patterns(js_content: str) -> Dict[str, List[str]]:
    """在JavaScript代码中查找常见模式"""
    patterns = {
        'md5': re.findall(r'md5\s*\([^)]+\)', js_content, re.IGNORECASE),
        'sha': re.findall(r'sha\d+\s*\([^)]+\)', js_content, re.IGNORECASE),
        'base64': re.findall(r'btoa\s*\([^)]+\)|atob\s*\([^)]+\)', js_content, re.IGNORECASE),
        'timestamp': re.findall(r'Date\.now\s*\(\)|getTime\s*\(\)', js_content, re.IGNORECASE),
        'sign': re.findall(r'sign\s*[:=]\s*[^,}]+', js_content, re.IGNORECASE),
    }
    
    return {k: v for k, v in patterns.items() if v}
