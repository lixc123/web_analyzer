import asyncio
import json
import hashlib
import logging
import uuid
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# 导入现有分析逻辑模块 (零修改复用)
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

import utils.analyzer as analyzer
from models.request_record import RequestRecord
import utils.file_helper as file_helper

from ..config import settings
from ..database import HybridStorage
from .cache_service import get_cache_service

logger = logging.getLogger(__name__)

class RequestAnalyzer:
    """请求分析器 - 提供各种分析功能"""
    
    def __init__(self):
        pass
    
    def analyze_entropy(self, requests: List[RequestRecord], min_entropy: float = 4.0) -> Dict:
        """熵值分析"""
        high_entropy_requests: List[Dict] = []
        for r in requests:
            try:
                fields = analyzer.detect_high_entropy_fields(r)
            except Exception:
                fields = []

            if not fields:
                continue

            hits = []
            for f in fields:
                if getattr(f, "entropy", 0.0) >= min_entropy or getattr(f, "is_suspicious", False):
                    hits.append({
                        "name": getattr(f, "name", ""),
                        "location": getattr(f, "location", ""),
                        "entropy": getattr(f, "entropy", 0.0),
                        "length": getattr(f, "length", 0),
                        "value_preview": getattr(f, "value_preview", ""),
                        "charset": getattr(f, "charset", None),
                    })

            if hits:
                high_entropy_requests.append({
                    "id": r.id,
                    "url": r.url,
                    "method": r.method,
                    "risk_level": "medium",
                    "reason": f"检测到 {len(hits)} 个高熵字段(>= {min_entropy})",
                    "high_entropy_fields": hits,
                })

        return {
            "high_entropy_requests": high_entropy_requests,
            "count": len(high_entropy_requests),
            "min_entropy": min_entropy,
        }
    
    def detect_sensitive_parameters(self, requests: List[RequestRecord], keywords: List[str] = None) -> Dict:
        """敏感参数分析"""

        suspicious: List[Dict] = []
        try:
            sensitive_records = analyzer.find_sensitive_requests(requests)
        except Exception:
            sensitive_records = []

        for r in sensitive_records:
            suspicious.append({
                "id": r.id,
                "url": r.url,
                "method": r.method,
                "risk_level": "high",
                "reason": "URL/headers/body 中出现疑似敏感字段关键词",
            })

        return {
            "suspicious_requests": suspicious,
            "count": len(suspicious),
            "keywords": keywords or [],
        }
    
    def identify_encryption_keywords(self, requests: List[RequestRecord]) -> Dict:
        """加密关键词分析"""

        suspicious: List[Dict] = []
        try:
            crypto_records = analyzer.find_crypto_suspected_requests(requests)
        except Exception:
            crypto_records = []

        for r in crypto_records:
            suspicious.append({
                "id": r.id,
                "url": r.url,
                "method": r.method,
                "risk_level": "low",
                "reason": "疑似包含加密/签名相关关键词或高随机性字段",
            })

        return {
            "encrypted_requests": suspicious,
            "count": len(suspicious),
        }

    def analyze_sensitive_params(self, requests: List[RequestRecord], keywords: List[str] = None) -> Dict:
        return self.detect_sensitive_parameters(requests, keywords)

    def analyze_encryption_keywords(self, requests: List[RequestRecord]) -> Dict:
        return self.identify_encryption_keywords(requests)

class AnalysisService:
    """
    数据分析服务 - 封装现有RequestAnalyzer等分析逻辑
    保持100%算法一致性，仅添加FastAPI兼容的异步接口
    """
    
    def __init__(self):
        self.cache_service = get_cache_service()
        # 直接使用现有RequestAnalyzer类 (零修改)
        self.analyzer = RequestAnalyzer()
        
        # 分析结果存储
        self.analysis_results: Dict[str, Dict] = {}
        
        # 自定义规则存储
        self.custom_rules: Dict[str, Dict] = {}
        
        # 异步处理的线程池
        self._executor = ThreadPoolExecutor(max_workers=4)
        
        # 数据预处理缓存
        self._preprocessing_cache: Dict[str, Any] = {}
    
    async def analyze(self, session_id: Optional[str] = None, 
                     requests_data: Optional[List[Dict]] = None, 
                     config: Dict = None) -> Dict:
        """
        执行综合分析
        支持传入session_id或直接传入请求数据
        """
        analysis_id = str(uuid.uuid4())
        analysis_type = config.get("analysis_type", "all")
        
        # 检查缓存
        cache_key_data = {
            "session_id": session_id,
            "requests_hash": self._hash_requests(requests_data) if requests_data else None,
            "config": config
        }
        
        cached_result = await self.cache_service.get_analysis_result(
            session_id or "direct", analysis_type, cache_key_data
        )
        
        if cached_result:
            logger.info(f"使用缓存的分析结果: {analysis_id}")
            return cached_result
        
        try:
            # 获取要分析的请求数据
            if requests_data:
                requests = requests_data
            elif session_id:
                requests = await self._load_session_requests(session_id)
            else:
                raise ValueError("必须提供 session_id 或 requests_data")
            
            if not requests:
                raise ValueError("没有可分析的请求数据")
            
            # 将请求数据转换为RequestRecord对象 (使用现有模型)
            request_records = []
            for req_data in requests:
                if isinstance(req_data, dict):
                    # 从字典创建RequestRecord对象
                    record = RequestRecord.from_dict(req_data)
                    request_records.append(record)
                elif isinstance(req_data, RequestRecord):
                    request_records.append(req_data)
            
            # 使用并发处理执行不同类型的分析
            results = {}
            suspicious_requests = []
            
            # 创建并发分析任务（使用字典避免索引依赖）
            analysis_tasks = {}

            if analysis_type in ["all", "entropy"]:
                analysis_tasks["entropy"] = asyncio.create_task(
                    asyncio.get_event_loop().run_in_executor(
                        self._executor,
                        self.analyzer.analyze_entropy,
                        request_records,
                        config.get("min_entropy", 4.0)
                    )
                )

            if analysis_type in ["all", "sensitive_params"]:
                analysis_tasks["sensitive_params"] = asyncio.create_task(
                    asyncio.get_event_loop().run_in_executor(
                        self._executor,
                        self.analyzer.detect_sensitive_parameters,
                        request_records,
                        config.get("sensitive_keywords", [])
                    )
                )

            # 等待所有分析任务完成
            if analysis_tasks:
                completed_results = await asyncio.gather(*analysis_tasks.values(), return_exceptions=True)
                analysis_results = dict(zip(analysis_tasks.keys(), completed_results))
            else:
                analysis_results = {}

            # 处理熵值分析结果
            if "entropy" in analysis_results and not isinstance(analysis_results["entropy"], Exception):
                entropy_results = analysis_results["entropy"]
                results["entropy"] = entropy_results
                suspicious_requests.extend(entropy_results.get("high_entropy_requests", []))

            # 处理敏感参数分析结果
            if "sensitive_params" in analysis_results and not isinstance(analysis_results["sensitive_params"], Exception):
                sensitive_results = analysis_results["sensitive_params"]
                results["sensitive_params"] = sensitive_results
                suspicious_requests.extend(sensitive_results.get("suspicious_requests", []))
            
            if analysis_type in ["all", "encryption_keywords"]:
                # 使用现有加密关键词识别 (零修改)
                encryption_results = await asyncio.get_event_loop().run_in_executor(
                    self._executor,
                    self.analyzer.identify_encryption_keywords,
                    request_records
                )
                results["encryption_keywords"] = encryption_results
                suspicious_requests.extend(encryption_results.get("encrypted_requests", []))
            
            # 应用自定义规则
            if config.get("custom_rules"):
                custom_results = await self._apply_custom_rules(
                    request_records, config["custom_rules"]
                )
                results["custom"] = custom_results
                suspicious_requests.extend(custom_results.get("matches", []))
            
            # 生成分析摘要
            summary = await self._generate_analysis_summary(results, request_records)
            
            # 去重可疑请求
            unique_suspicious = self._deduplicate_suspicious_requests(suspicious_requests)
            
            analysis_result = {
                "analysis_id": analysis_id,
                "session_id": session_id,
                "analysis_type": analysis_type,
                "results": results,
                "summary": summary,
                "suspicious_requests": unique_suspicious,
                "timestamp": datetime.now().isoformat(),
                "config": config,
                "total_requests_analyzed": len(request_records)
            }
            
            # 存储分析结果
            self.analysis_results[analysis_id] = analysis_result
            
            # 缓存结果
            await self.cache_service.set_analysis_result(
                session_id or "direct", analysis_type, cache_key_data, analysis_result
            )
            
            logger.info(f"分析完成: {analysis_id}, 分析了 {len(request_records)} 个请求")
            return analysis_result
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            raise
    
    async def analyze_entropy(self, session_id: str, min_entropy: float = 4.0) -> List[Dict]:
        """单独执行熵值分析"""
        requests = await self._load_session_requests(session_id)

        # 统一类型转换逻辑
        request_records = []
        for req in requests:
            if isinstance(req, dict):
                request_records.append(RequestRecord.from_dict(req))
            elif isinstance(req, RequestRecord):
                request_records.append(req)

        # 使用现有熵值分析算法 (零修改)
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            self.analyzer.analyze_entropy,
            request_records,
            min_entropy
        )

        return result.get("high_entropy_requests", [])
    
    async def analyze_sensitive_params(self, session_id: str, custom_keywords: List[str] = None) -> List[Dict]:
        """单独执行敏感参数分析"""
        requests = await self._load_session_requests(session_id)

        # 统一类型转换逻辑
        request_records = []
        for req in requests:
            if isinstance(req, dict):
                request_records.append(RequestRecord.from_dict(req))
            elif isinstance(req, RequestRecord):
                request_records.append(req)

        # 使用现有敏感参数检测 (零修改)
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            self.analyzer.detect_sensitive_parameters,
            request_records,
            custom_keywords or []
        )

        return result.get("suspicious_requests", [])
    
    async def analyze_encryption_keywords(self, session_id: str) -> List[Dict]:
        """单独执行加密关键词分析"""
        requests = await self._load_session_requests(session_id)

        # 统一类型转换逻辑
        request_records = []
        for req in requests:
            if isinstance(req, dict):
                request_records.append(RequestRecord.from_dict(req))
            elif isinstance(req, RequestRecord):
                request_records.append(req)

        # 使用现有加密关键词识别 (零修改)
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            self.analyzer.identify_encryption_keywords,
            request_records
        )

        return result.get("encrypted_requests", [])
    
    async def get_analysis_summary(self, session_id: str) -> Dict:
        """获取会话的分析摘要"""
        # 查找该会话的所有分析结果
        session_analyses = [
            result for result in self.analysis_results.values()
            if result.get("session_id") == session_id
        ]
        
        if not session_analyses:
            # 如果没有现有分析，执行一次快速分析
            analysis = await self.analyze(session_id=session_id, config={"analysis_type": "all"})
            return analysis["summary"]
        
        # 合并多次分析的摘要
        combined_summary = {
            "total_analyses": len(session_analyses),
            "latest_analysis": session_analyses[-1]["timestamp"],
            "total_suspicious_requests": 0,
            "risk_levels": {"high": 0, "medium": 0, "low": 0},
            "analysis_types": []
        }
        
        for analysis in session_analyses:
            summary = analysis.get("summary", {})
            combined_summary["total_suspicious_requests"] += len(analysis.get("suspicious_requests", []))
            combined_summary["analysis_types"].append(analysis["analysis_type"])
            
            # 合并风险级别统计
            for level in ["high", "medium", "low"]:
                combined_summary["risk_levels"][level] += summary.get("risk_levels", {}).get(level, 0)
        
        return combined_summary
    
    async def create_custom_rule(self, rule_name: str, rule_config: Dict) -> str:
        """创建自定义分析规则"""
        rule_id = str(uuid.uuid4())
        
        rule_data = {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "config": rule_config,
            "created_at": datetime.now().isoformat(),
            "enabled": True
        }
        
        self.custom_rules[rule_id] = rule_data
        
        # 持久化自定义规则
        await self._save_custom_rules()
        
        logger.info(f"创建自定义规则: {rule_name} ({rule_id})")
        return rule_id
    
    async def list_rules(self) -> Dict:
        """列出所有分析规则"""
        # 内置规则
        builtin_rules = {
            "entropy": {
                "name": "高熵字段检测",
                "description": "检测高熵值字段，可能包含加密数据",
                "type": "builtin"
            },
            "sensitive_params": {
                "name": "敏感参数检测", 
                "description": "检测可能包含敏感信息的参数",
                "type": "builtin"
            },
            "encryption_keywords": {
                "name": "加密关键词识别",
                "description": "识别加密相关的关键词和模式",
                "type": "builtin"
            }
        }
        
        return {
            "builtin_rules": builtin_rules,
            "custom_rules": self.custom_rules
        }
    
    async def get_analysis_history(self, session_id: str, limit: int = 20, offset: int = 0) -> List[Dict]:
        """获取分析历史记录"""
        session_analyses = [
            {
                "analysis_id": aid,
                "analysis_type": result["analysis_type"],
                "timestamp": result["timestamp"],
                "suspicious_count": len(result.get("suspicious_requests", [])),
                "summary": result.get("summary", {})
            }
            for aid, result in self.analysis_results.items()
            if result.get("session_id") == session_id
        ]
        
        # 按时间倒序排序
        session_analyses.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return session_analyses[offset:offset + limit]
    
    async def compare_results(self, analysis_ids: List[str]) -> Dict:
        """比较多个分析结果"""
        if len(analysis_ids) < 2:
            raise ValueError("至少需要2个分析结果进行比较")
        
        analyses = []
        for aid in analysis_ids:
            if aid not in self.analysis_results:
                raise ValueError(f"分析结果 {aid} 不存在")
            analyses.append(self.analysis_results[aid])
        
        comparison = {
            "analysis_ids": analysis_ids,
            "comparison_time": datetime.now().isoformat(),
            "metrics": {
                "suspicious_requests": [len(a.get("suspicious_requests", [])) for a in analyses],
                "analysis_types": [a["analysis_type"] for a in analyses],
                "request_counts": [a.get("total_requests_analyzed", 0) for a in analyses]
            },
            "differences": [],
            "common_patterns": []
        }
        
        # 分析差异和共同模式
        all_suspicious = []
        for analysis in analyses:
            all_suspicious.extend(analysis.get("suspicious_requests", []))
        
        # 统计共同出现的可疑请求
        url_counts = {}
        for req in all_suspicious:
            url = req.get("url", "")
            url_counts[url] = url_counts.get(url, 0) + 1
        
        common_patterns = [
            {"url": url, "occurrences": count}
            for url, count in url_counts.items()
            if count > 1
        ]
        
        comparison["common_patterns"] = common_patterns
        return comparison
    
    async def export_analysis(self, analysis_id: str, format: str = "json") -> Any:
        """导出分析结果"""
        if analysis_id not in self.analysis_results:
            raise ValueError(f"分析结果 {analysis_id} 不存在")
        
        result = self.analysis_results[analysis_id]
        
        if format == "json":
            return result
        elif format == "csv":
            return await self._export_analysis_to_csv(result)
        elif format == "pdf":
            return await self._export_analysis_to_pdf(result)
        else:
            raise ValueError(f"不支持的导出格式: {format}")
    
    async def _load_session_requests(self, session_id: str) -> List[Dict]:
        """从存储中加载会话请求数据（异步优化版本）"""
        try:
            # 优先从session级别存储异步加载
            session_requests = await HybridStorage.load_session_requests_async(session_id)
            
            if session_requests:
                logger.info(f"从session级别存储加载了 {len(session_requests)} 个请求")
                return session_requests
            
            # 向后兼容：如果session级别没有数据，尝试从全局requests.json异步加载
            requests_file = HybridStorage.get_requests_json_path()
            if not os.path.exists(requests_file):
                logger.warning(f"会话 {session_id} 没有找到任何请求数据")
                return []
            
            all_requests = await HybridStorage.load_json_data_async(requests_file)
            
            # 过滤指定会话的请求
            session_requests = [
                req for req in all_requests 
                if req.get("session_id") == session_id
            ]
            
            logger.info(f"从全局存储加载了 {len(session_requests)} 个会话请求")
            return session_requests
            
        except Exception as e:
            logger.error(f"加载会话请求失败: {e}")
            return []
    
    def _hash_requests(self, requests_data: List[Dict]) -> str:
        """计算请求数据的哈希值用于缓存"""
        if not requests_data:
            return ""
        
        # 创建请求数据的简化版本用于哈希
        simplified = []
        for req in requests_data[:100]:  # 只取前100个请求计算哈希
            simplified.append({
                "url": req.get("url", ""),
                "method": req.get("method", ""),
                "status": req.get("status") if req.get("status") is not None else req.get("status_code", 0)
            })
        
        data_str = json.dumps(simplified, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()
    
    async def _apply_custom_rules(self, request_records: List[RequestRecord], rules: Dict) -> Dict:
        """应用自定义分析规则"""
        matches = []
        
        for rule_id, rule_config in rules.items():
            if rule_id in self.custom_rules:
                rule = self.custom_rules[rule_id]
                if not rule.get("enabled", True):
                    continue
                
                # 应用规则逻辑
                rule_matches = await self._execute_custom_rule(request_records, rule["config"])
                matches.extend(rule_matches)
        
        return {"matches": matches, "rules_applied": len(rules)}
    
    async def _execute_custom_rule(self, request_records: List[RequestRecord], rule_config: Dict) -> List[Dict]:
        """执行单个自定义规则"""
        matches = []
        
        # 这里可以实现复杂的自定义规则逻辑
        # 目前实现一个简单的关键词匹配规则
        keywords = rule_config.get("keywords", [])
        fields = rule_config.get("fields", ["url", "request_body", "response_body"])
        
        for record in request_records:
            record_dict = record.to_dict() if hasattr(record, 'to_dict') else record
            
            for field in fields:
                field_value = str(record_dict.get(field, "")).lower()
                
                for keyword in keywords:
                    if keyword.lower() in field_value:
                        matches.append({
                            "url": record_dict.get("url", ""),
                            "method": record_dict.get("method", ""),
                            "matched_field": field,
                            "matched_keyword": keyword,
                            "rule_type": "custom"
                        })
                        break
        
        return matches
    
    async def _generate_analysis_summary(self, results: Dict, request_records: List) -> Dict:
        """生成分析摘要"""
        summary = {
            "total_requests": len(request_records),
            "analysis_types": list(results.keys()),
            "suspicious_count": 0,
            "risk_levels": {"high": 0, "medium": 0, "low": 0},
            "top_issues": [],
            "recommendations": []
        }
        
        # 统计可疑请求数量和风险级别
        for analysis_type, result in results.items():
            if analysis_type == "entropy":
                high_entropy = result.get("high_entropy_requests", [])
                summary["suspicious_count"] += len(high_entropy)
                summary["risk_levels"]["medium"] += len(high_entropy)
                
            elif analysis_type == "sensitive_params":
                sensitive = result.get("suspicious_requests", [])
                summary["suspicious_count"] += len(sensitive)
                summary["risk_levels"]["high"] += len(sensitive)
                
            elif analysis_type == "encryption_keywords":
                encrypted = result.get("encrypted_requests", [])
                summary["suspicious_count"] += len(encrypted)
                summary["risk_levels"]["low"] += len(encrypted)
        
        # 生成建议
        if summary["risk_levels"]["high"] > 0:
            summary["recommendations"].append("发现高风险敏感参数，建议立即检查相关请求")
        
        if summary["risk_levels"]["medium"] > 5:
            summary["recommendations"].append("发现多个高熵字段，可能包含加密数据")
        
        return summary
    
    def _deduplicate_suspicious_requests(self, suspicious_requests: List[Dict]) -> List[Dict]:
        """去重可疑请求"""
        seen = set()
        unique_requests = []
        
        for req in suspicious_requests:
            # 使用URL+方法作为去重键
            key = f"{req.get('url', '')}:{req.get('method', '')}"
            if key not in seen:
                seen.add(key)
                unique_requests.append(req)
        
        return unique_requests
    
    async def _save_custom_rules(self):
        """保存自定义规则到文件"""
        rules_file = os.path.join(settings.data_dir, "custom_rules.json")
        
        try:
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(self.custom_rules, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存自定义规则失败: {e}")
    
    async def _export_analysis_to_csv(self, result: Dict) -> str:
        """导出分析结果为CSV"""
        import csv
        import io
        
        output = io.StringIO()
        
        # 导出可疑请求列表
        suspicious = result.get("suspicious_requests", [])
        if suspicious:
            fieldnames = set()
            for req in suspicious:
                fieldnames.update(req.keys())
            
            writer = csv.DictWriter(output, fieldnames=list(fieldnames))
            writer.writeheader()
            writer.writerows(suspicious)
        
        return output.getvalue()
    
    async def _export_analysis_to_pdf(self, result: Dict) -> bytes:
        """导出分析结果为PDF"""
        # 这里可以使用reportlab等库生成PDF报告
        # 目前返回简单的文本格式
        
        report = f"""
分析报告
========

分析ID: {result['analysis_id']}
分析时间: {result['timestamp']}
分析类型: {result['analysis_type']}

摘要:
- 总请求数: {result['summary']['total_requests']}
- 可疑请求数: {result['summary']['suspicious_count']}
- 高风险: {result['summary']['risk_levels']['high']}
- 中风险: {result['summary']['risk_levels']['medium']}
- 低风险: {result['summary']['risk_levels']['low']}

建议:
""" + "\n".join(f"- {rec}" for rec in result['summary']['recommendations'])
        
        return report.encode('utf-8')
