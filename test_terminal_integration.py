#!/usr/bin/env python3
"""
Terminal Integration Test Script
测试Terminal功能集成是否成功
"""

import requests
import json
import time
import sys
import os
from pathlib import Path

def test_backend_api():
    """测试后端API是否正常"""
    try:
        # 测试健康检查
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("[OK] 后端服务正常运行")
            return True
        else:
            print(f"[FAIL] 后端健康检查失败: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] 无法连接到后端服务: {e}")
        return False

def test_terminal_sessions_api():
    """测试Terminal会话API"""
    try:
        response = requests.get("http://localhost:8000/api/v1/terminal/sessions", timeout=10)
        if response.status_code == 200:
            sessions = response.json()
            print(f"[OK] Terminal会话API正常，发现 {len(sessions)} 个会话:")
            for session in sessions[:3]:  # 只显示前3个
                print(f"  - {session['name']} ({session['type']})")
            if len(sessions) > 3:
                print(f"  ... 还有 {len(sessions) - 3} 个会话")
            return True
        else:
            print(f"[FAIL] Terminal会话API失败: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] 无法连接到Terminal会话API: {e}")
        return False

def test_terminal_service():
    """测试Node.js终端服务"""
    try:
        response = requests.get("http://localhost:3001/health", timeout=5)
        if response.status_code == 200:
            print("[OK] Node.js终端服务正常运行")
            return True
        else:
            print(f"[FAIL] Node.js终端服务健康检查失败: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] 无法连接到Node.js终端服务: {e}")
        print("   请确保运行了启动脚本或手动启动了终端服务")
        return False

def test_frontend_access():
    """测试前端是否可访问"""
    try:
        response = requests.get("http://localhost:3000", timeout=5)  # 前端通常在3000端口
        if response.status_code == 200:
            print("[OK] 前端服务可访问")
            return True
        else:
            print(f"[FAIL] 前端服务访问失败: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        # 前端可能在5173端口(Vite dev server)
        try:
            response = requests.get("http://localhost:5173", timeout=5)
            if response.status_code == 200:
                print("[OK] 前端服务可访问 (Vite开发服务器)")
                return True
        except:
            pass
        print(f"[FAIL] 无法连接到前端服务: {e}")
        return False

def check_project_structure():
    """检查项目结构是否完整"""
    project_root = Path(__file__).parent
    required_files = [
        "backend/app/api/v1/terminal.py",
        "backend/terminal_service/package.json",
        "backend/terminal_service/server.js",
        "backend/terminal_service/public/index.html",
        "frontend/src/pages/Terminal/index.tsx",
        "scripts/setup_and_start.bat",
        "scripts/simple_start.bat"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not (project_root / file_path).exists():
            missing_files.append(file_path)
    
    if not missing_files:
        print("[OK] 项目结构完整")
        return True
    else:
        print("[FAIL] 缺少以下文件:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False

def main():
    print("=" * 50)
    print("      Terminal Integration Test")
    print("=" * 50)
    print()
    
    # 检查项目结构
    print("1. 检查项目结构...")
    structure_ok = check_project_structure()
    print()
    
    # 测试后端服务
    print("2. 测试后端服务...")
    backend_ok = test_backend_api()
    print()
    
    # 测试Terminal API
    print("3. 测试Terminal API...")
    terminal_api_ok = test_terminal_sessions_api()
    print()
    
    # 测试Node.js终端服务
    print("4. 测试Node.js终端服务...")
    terminal_service_ok = test_terminal_service()
    print()
    
    # 测试前端服务
    print("5. 测试前端服务...")
    frontend_ok = test_frontend_access()
    print()
    
    # 总结
    print("=" * 50)
    print("           测试结果总结")
    print("=" * 50)
    
    total_tests = 5
    passed_tests = sum([structure_ok, backend_ok, terminal_api_ok, terminal_service_ok, frontend_ok])
    
    print(f"通过测试: {passed_tests}/{total_tests}")
    print()
    
    if passed_tests == total_tests:
        print("[OK] 所有测试通过！Terminal功能集成成功！")
        print()
        print("使用指南:")
        print("1. 运行 scripts/setup_and_start.bat 或 scripts/simple_start.bat")
        print("2. 在浏览器中访问 http://localhost:3000")
        print("3. 点击侧边栏的 'Qwen终端' 菜单")
        print("4. 选择会话目录并点击 '切换到此会话'")
        print("5. 在终端中可以使用qwen命令")
        
    elif passed_tests >= 3:
        print("[WARN] 部分功能可用，但存在一些问题需要解决")
        if not terminal_service_ok:
            print("- 需要启动Node.js终端服务")
        if not frontend_ok:
            print("- 需要启动前端服务")
            
    else:
        print("[FAIL] 多个关键服务未运行，请先启动所需服务")
        print("运行: scripts/setup_and_start.bat")
    
    print()
    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
