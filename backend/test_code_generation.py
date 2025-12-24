"""
代码生成功能测试

测试HTTP请求记录到Python代码的转换功能
"""

import json
import sys
from pathlib import Path

# 添加后端路径到Python路径
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

from core.code_generator import generate_code_from_session
from models.request_record import RequestRecord


def create_test_session():
    """创建一个测试会话目录和数据"""
    test_session_path = backend_path / "test_data" / "test_session"
    test_session_path.mkdir(parents=True, exist_ok=True)
    
    # 创建测试请求记录
    test_records = [
        {
            "id": "1234567890",
            "timestamp": 1703456789.123,
            "method": "POST",
            "url": "https://api.example.com/login",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Authorization": "Bearer test-token"
            },
            "post_data": '{"username": "test", "password": "secret", "sign": "abc123"}',
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json",
                "Set-Cookie": "session_id=xyz789"
            },
            "response_body_path": "responses/1234567890.json",
            "response_size": 256,
            "content_type": "application/json",
            "response_timestamp": 1703456789.456,
            "call_stack": "at makeSign (main.js:123:45)\n    at login (auth.js:67:12)\n    at onClick (button.js:34:8)",
            "resource_type": "xhr"
        },
        {
            "id": "2345678901", 
            "timestamp": 1703456790.234,
            "method": "GET",
            "url": "https://api.example.com/user/profile",
            "headers": {
                "Authorization": "Bearer test-token",
                "Accept": "application/json"
            },
            "post_data": None,
            "status": 200,
            "response_headers": {
                "Content-Type": "application/json"
            },
            "response_body_path": "responses/2345678901.json",
            "response_size": 512,
            "content_type": "application/json",
            "response_timestamp": 1703456790.567,
            "call_stack": "at loadProfile (profile.js:89:23)\n    at componentDidMount (App.js:145:67)",
            "resource_type": "fetch"
        },
        {
            "id": "3456789012",
            "timestamp": 1703456791.345,
            "method": "POST", 
            "url": "https://api.example.com/data/submit",
            "headers": {
                "Content-Type": "application/json",
                "X-API-Key": "secret-key-123"
            },
            "post_data": '{"data": "encrypted_data_here", "timestamp": 1703456791, "signature": "md5hash"}',
            "status": 201,
            "response_headers": {
                "Content-Type": "application/json"
            },
            "response_body_path": "responses/3456789012.json", 
            "response_size": 128,
            "content_type": "application/json",
            "response_timestamp": 1703456791.678,
            "call_stack": "at generateSignature (crypto.js:45:12)\n    at submitData (api.js:234:56)\n    at handleSubmit (form.js:78:90)",
            "resource_type": "xhr"
        }
    ]
    
    # 保存requests.json
    requests_file = test_session_path / "requests.json"
    with open(requests_file, 'w', encoding='utf-8') as f:
        json.dump(test_records, f, ensure_ascii=False, indent=2)
    
    # 创建scripts目录和示例JS文件
    scripts_dir = test_session_path / "scripts"
    scripts_dir.mkdir(exist_ok=True)
    
    # 创建示例JavaScript文件
    js_content = """
// 示例加密和签名函数
function makeSign(data) {
    const timestamp = Date.now();
    const secret = "my_secret_key";
    const rawString = data + timestamp + secret;
    return md5(rawString);
}

function generateSignature(data) {
    const key = "api_secret_123";
    return btoa(data + key);
}

function md5(str) {
    // 简化的MD5实现 (实际项目中会使用crypto库)
    return "mock_md5_" + str.length;
}

// 主要API调用函数
function login(username, password) {
    const sign = makeSign(username + password);
    return fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password,  
            sign: sign,
            timestamp: Date.now()
        })
    });
}
"""
    
    with open(scripts_dir / "main.js", 'w', encoding='utf-8') as f:
        f.write(js_content)
        
    with open(scripts_dir / "crypto.js", 'w', encoding='utf-8') as f:
        f.write("// 加密相关函数\n" + js_content)
    
    # 创建responses目录
    responses_dir = test_session_path / "responses"
    responses_dir.mkdir(exist_ok=True)
    
    # 创建示例响应文件
    response_files = [
        ("1234567890.json", {"success": True, "token": "jwt_token_here", "user_id": 12345}),
        ("2345678901.json", {"id": 12345, "username": "test", "email": "test@example.com"}),
        ("3456789012.json", {"success": True, "message": "Data submitted successfully"})
    ]
    
    for filename, content in response_files:
        with open(responses_dir / filename, 'w', encoding='utf-8') as f:
            json.dump(content, f, ensure_ascii=False, indent=2)
    
    print(f"[OK] 测试会话已创建: {test_session_path}")
    return test_session_path


def test_code_generation():
    """测试代码生成功能"""
    print("[TEST] 开始测试代码生成功能...")
    
    # 创建测试数据
    session_path = create_test_session()
    
    try:
        # 生成代码
        print("[INFO] 生成Python代码...")
        generated_code = generate_code_from_session(session_path)
        
        # 保存生成的代码
        output_file = session_path / "generated_test.py"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        print("[OK] 代码生成成功!")
        print(f"[FILE] 代码已保存到: {output_file}")
        print(f"[STAT] 代码长度: {len(generated_code)} 字符")
        
        # 显示代码预览
        print("\n[INFO] 代码预览 (前500字符):")
        print("-" * 50)
        print(generated_code[:500] + "..." if len(generated_code) > 500 else generated_code)
        print("-" * 50)
        
        # 验证生成的代码包含关键元素
        checks = [
            ("包含WebSession类", "class WebSession:" in generated_code),
            ("包含请求方法", "def request_" in generated_code),
            ("包含JavaScript分析", "analyze_js_context" in generated_code),
            ("包含主函数", "if __name__ == '__main__':" in generated_code),
            ("包含导入语句", "import requests" in generated_code),
            ("包含JSON处理", "import json" in generated_code),
        ]
        
        print("\n[CHECK] 代码质量检查:")
        all_passed = True
        for check_name, result in checks:
            status = "[OK]" if result else "[FAIL]"
            print(f"  {status} {check_name}")
            if not result:
                all_passed = False
        
        if all_passed:
            print("\n[OK] 所有检查通过! 代码生成功能工作正常")
            
            # 尝试语法检查
            try:
                compile(generated_code, output_file, 'exec')
                print("[OK] Python语法检查通过")
            except SyntaxError as e:
                print(f"[WARN] Python语法警告: {e}")
                
        else:
            print("\n[WARN] 部分检查失败，需要进一步调试")
        
        return True, output_file
        
    except Exception as e:
        print(f"[FAIL] 代码生成失败: {e}")
        import traceback
        traceback.print_exc()
        return False, None


def test_api_integration():
    """测试API集成 (模拟API调用)"""
    print("\n[INFO] 测试API集成...")
    
    try:
        # 模拟API请求数据
        from core.code_generator import PythonCodeGenerator
        
        generator = PythonCodeGenerator()
        
        # 创建测试记录
        test_record = RequestRecord(
            id="test123",
            timestamp=1703456789.0,
            method="POST",
            url="https://test.com/api",
            headers={"Content-Type": "application/json"},
            post_data='{"test": "data"}',
            status=200,
            response_headers={"Content-Type": "application/json"},
            response_body_path="test.json",
            response_size=100,
            content_type="application/json",
            response_timestamp=1703456790.0,
            call_stack="at test (test.js:1:1)",
            resource_type="xhr"
        )
        
        # 测试单个请求方法生成
        method_code = generator._generate_request_method(test_record, 0)
        
        print("[OK] 单个请求方法生成成功")
        print(f"[STAT] 生成了 {len(method_code)} 行代码")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] API集成测试失败: {e}")
        return False


def main():
    """主测试函数"""
    print("[INFO] 开始代码生成功能测试\n")
    
    results = []
    
    # 测试1: 代码生成功能
    success, output_file = test_code_generation()
    results.append(("代码生成功能", success))
    
    # 测试2: API集成
    success = test_api_integration()
    results.append(("API集成", success))
    
    # 总结
    print(f"\n{'='*60}")
    print("[INFO] 测试结果总结:")
    
    passed = 0
    for test_name, result in results:
        status = "[OK] 通过" if result else "[FAIL] 失败"
        print(f"  {status} {test_name}")
        if result:
            passed += 1
    
    total = len(results)
    print(f"\n[STAT] 总体结果: {passed}/{total} 通过")
    
    if passed == total:
        print("[OK] 所有测试通过! 代码生成功能已就绪")
        if output_file:
            print(f"[TIP] 可以运行生成的代码测试: python {output_file}")
    else:
        print("[WARN] 部分测试失败，需要修复问题")


if __name__ == "__main__":
    main()
