from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging

from ...database import get_db
from ...services.analysis_service import AnalysisService
from ....utils.js_beautifier import beautify_js
from ....utils.dependency_analyzer import DependencyAnalyzer
from ....utils.replay_validator import ReplayValidator

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models
class AnalysisConfig(BaseModel):
    analysis_type: str  # entropy, sensitive_params, encryption_keywords, all
    min_entropy: float = 4.0
    sensitive_keywords: List[str] = []
    custom_rules: Dict[str, Any] = {}

class AnalysisRequest(BaseModel):
    session_id: Optional[str] = None
    requests_data: Optional[List[Dict]] = None  # 可直接传入请求数据
    config: AnalysisConfig

class AnalysisResult(BaseModel):
    analysis_id: str
    session_id: Optional[str]
    analysis_type: str
    results: Dict[str, Any]
    summary: Dict[str, Any]
    suspicious_requests: List[Dict]
    timestamp: str

class SensitiveParamsResult(BaseModel):
    request_id: str
    url: str
    method: str
    suspicious_params: List[Dict]
    risk_level: str

@router.post("/analyze", response_model=AnalysisResult)
async def analyze_requests(
    request: AnalysisRequest,
    db: Session = Depends(get_db)
):
    """分析网络请求数据"""
    try:
        analysis_service = AnalysisService()
        
        # 执行分析
        result = await analysis_service.analyze(
            session_id=request.session_id,
            requests_data=request.requests_data,
            config=request.config.dict()
        )
        
        return AnalysisResult(**result)
        
    except Exception as e:
        logger.error(f"分析请求失败: {e}")
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")

@router.get("/entropy/{session_id}")
async def analyze_entropy(
    session_id: str,
    min_entropy: float = 4.0,
    db: Session = Depends(get_db)
):
    """熵值分析 - 检测高熵字段"""
    try:
        analysis_service = AnalysisService()
        result = await analysis_service.analyze_entropy(session_id, min_entropy)
        
        return {
            "session_id": session_id,
            "analysis_type": "entropy",
            "min_entropy": min_entropy,
            "high_entropy_fields": result
        }
        
    except Exception as e:
        logger.error(f"熵值分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"熵值分析失败: {str(e)}")

@router.get("/sensitive-params/{session_id}")
async def analyze_sensitive_params(
    session_id: str,
    custom_keywords: Optional[str] = None,  # 逗号分隔的关键词
    db: Session = Depends(get_db)
):
    """敏感参数分析"""
    try:
        analysis_service = AnalysisService()
        
        keywords = []
        if custom_keywords:
            keywords = [k.strip() for k in custom_keywords.split(',')]
            
        result = await analysis_service.analyze_sensitive_params(session_id, keywords)
        
        return {
            "session_id": session_id,
            "analysis_type": "sensitive_params",
            "custom_keywords": keywords,
            "results": result
        }
        
    except Exception as e:
        logger.error(f"敏感参数分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"敏感参数分析失败: {str(e)}")

@router.get("/encryption-keywords/{session_id}")
async def analyze_encryption_keywords(
    session_id: str,
    db: Session = Depends(get_db)
):
    """加密关键词分析"""
    try:
        analysis_service = AnalysisService()
        result = await analysis_service.analyze_encryption_keywords(session_id)
        
        return {
            "session_id": session_id,
            "analysis_type": "encryption_keywords",
            "results": result
        }
        
    except Exception as e:
        logger.error(f"加密关键词分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"加密关键词分析失败: {str(e)}")

@router.get("/summary/{session_id}")
async def get_analysis_summary(
    session_id: str,
    db: Session = Depends(get_db)
):
    """获取分析摘要"""
    try:
        analysis_service = AnalysisService()
        summary = await analysis_service.get_analysis_summary(session_id)
        
        return {
            "session_id": session_id,
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"获取分析摘要失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取分析摘要失败: {str(e)}")

@router.post("/custom-rules")
async def create_custom_analysis_rule(
    rule_name: str,
    rule_config: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """创建自定义分析规则"""
    try:
        analysis_service = AnalysisService()
        rule_id = await analysis_service.create_custom_rule(rule_name, rule_config)
        
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "status": "created",
            "message": "自定义规则创建成功"
        }
        
    except Exception as e:
        logger.error(f"创建自定义规则失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建自定义规则失败: {str(e)}")

@router.get("/rules")
async def list_analysis_rules(db: Session = Depends(get_db)):
    """列出所有分析规则"""
    try:
        analysis_service = AnalysisService()
        rules = await analysis_service.list_rules()
        
        return {"rules": rules}
        
    except Exception as e:
        logger.error(f"获取规则列表失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取规则列表失败: {str(e)}")

@router.get("/history/{session_id}")
async def get_analysis_history(
    session_id: str,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """获取分析历史记录"""
    try:
        analysis_service = AnalysisService()
        history = await analysis_service.get_analysis_history(
            session_id, limit=limit, offset=offset
        )
        
        return {
            "session_id": session_id,
            "history": history,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"获取分析历史失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取分析历史失败: {str(e)}")

@router.post("/compare")
async def compare_analysis_results(
    analysis_ids: List[str],
    db: Session = Depends(get_db)
):
    """比较多个分析结果"""
    try:
        analysis_service = AnalysisService()
        comparison = await analysis_service.compare_results(analysis_ids)
        
        return {
            "analysis_ids": analysis_ids,
            "comparison": comparison
        }
        
    except Exception as e:
        logger.error(f"比较分析结果失败: {e}")
        raise HTTPException(status_code=500, detail=f"比较分析结果失败: {str(e)}")

@router.post("/export/{analysis_id}")
async def export_analysis_result(
    analysis_id: str,
    format: str = "json",  # json, csv, pdf
    db: Session = Depends(get_db)
):
    """导出分析结果"""
    try:
        analysis_service = AnalysisService()
        
        if format not in ["json", "csv", "pdf"]:
            raise HTTPException(status_code=400, detail="支持的格式: json, csv, pdf")
        
        export_data = await analysis_service.export_analysis(analysis_id, format)
        
        return {
            "analysis_id": analysis_id,
            "format": format,
            "data": export_data,
            "message": "分析结果导出成功"
        }
        
    except Exception as e:
        logger.error(f"导出分析结果失败: {e}")
        raise HTTPException(status_code=500, detail=f"导出分析结果失败: {str(e)}")

class BeautifyRequest(BaseModel):
    code: str

@router.post("/beautify-js")
async def beautify_javascript(request: BeautifyRequest):
    """美化JavaScript代码"""
    try:
        beautified = beautify_js(request.code)
        return {"beautified_code": beautified}
    except Exception as e:
        logger.error(f"代码美化失败: {e}")
        raise HTTPException(status_code=500, detail=f"代码美化失败: {str(e)}")

class DependencyRequest(BaseModel):
    requests: List[Dict[str, Any]]

@router.post("/dependency-graph")
async def analyze_dependency_graph(request: DependencyRequest):
    """分析请求依赖关系图"""
    try:
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_dependencies(request.requests)
        return result
    except Exception as e:
        logger.error(f"依赖关系分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"依赖关系分析失败: {str(e)}")

@router.post("/replay-validate")
async def replay_and_validate(request: DependencyRequest):
    """重放请求并验证"""
    try:
        validator = ReplayValidator()
        result = await validator.replay_requests(request.requests)
        return result
    except Exception as e:
        logger.error(f"重放验证失败: {e}")
        raise HTTPException(status_code=500, detail=f"重放验证失败: {str(e)}")

@router.post("/signature-analysis")
async def analyze_signature(request: DependencyRequest):
    """分析请求签名"""
    try:
        from backend.utils.signature_analyzer import SignatureAnalyzer
        analyzer = SignatureAnalyzer()
        result = analyzer.analyze_requests(request.requests)
        return result
    except Exception as e:
        logger.error(f"签名分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"签名分析失败: {str(e)}")
