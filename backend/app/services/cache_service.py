import asyncio
import json
import logging
from typing import Any, Optional, Dict, List
from cachetools import TTLCache, LRUCache
from datetime import datetime, timedelta
from ..config import settings

logger = logging.getLogger(__name__)

class CacheService:
    """内存缓存服务 - 使用cachetools实现"""
    
    def __init__(self):
        # TTL缓存 - 分析结果缓存（1小时过期）
        self.analysis_cache = TTLCache(
            maxsize=settings.cache_max_size,
            ttl=settings.cache_ttl
        )
        
        # LRU缓存 - API响应缓存（最大1000条记录）
        self.api_cache = LRUCache(maxsize=settings.cache_max_size)
        
        # 模型调用结果缓存 - 减少重复请求
        self.model_cache = TTLCache(
            maxsize=500,
            ttl=7200  # 2小时过期
        )
        
        # 缓存统计
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }
    
    def _generate_key(self, prefix: str, **kwargs) -> str:
        """生成缓存键"""
        key_parts = [prefix]
        for k, v in sorted(kwargs.items()):
            if isinstance(v, (dict, list)):
                v = json.dumps(v, sort_keys=True)
            key_parts.append(f"{k}:{v}")
        return "|".join(key_parts)
    
    async def get_analysis_result(self, session_id: str, analysis_type: str, config: Dict) -> Optional[Any]:
        """获取分析结果缓存"""
        key = self._generate_key("analysis", session_id=session_id, type=analysis_type, config=config)
        
        if key in self.analysis_cache:
            self.stats["hits"] += 1
            logger.debug(f"缓存命中: {key}")
            return self.analysis_cache[key]
        
        self.stats["misses"] += 1
        return None
    
    async def set_analysis_result(self, session_id: str, analysis_type: str, config: Dict, result: Any):
        """设置分析结果缓存"""
        key = self._generate_key("analysis", session_id=session_id, type=analysis_type, config=config)
        self.analysis_cache[key] = result
        logger.debug(f"缓存设置: {key}")
    
    async def get_api_response(self, endpoint: str, params: Dict) -> Optional[Any]:
        """获取API响应缓存"""
        key = self._generate_key("api", endpoint=endpoint, params=params)
        
        if key in self.api_cache:
            self.stats["hits"] += 1
            logger.debug(f"API缓存命中: {key}")
            return self.api_cache[key]
        
        self.stats["misses"] += 1
        return None
    
    async def set_api_response(self, endpoint: str, params: Dict, response: Any):
        """设置API响应缓存"""
        key = self._generate_key("api", endpoint=endpoint, params=params)
        self.api_cache[key] = response
        logger.debug(f"API缓存设置: {key}")
    
    async def get_model_result(self, model: str, input_hash: str, params: Dict) -> Optional[Any]:
        """获取模型调用结果缓存"""
        key = self._generate_key("model", model=model, input=input_hash, params=params)
        
        if key in self.model_cache:
            self.stats["hits"] += 1
            logger.debug(f"模型缓存命中: {key}")
            return self.model_cache[key]
        
        self.stats["misses"] += 1
        return None
    
    async def set_model_result(self, model: str, input_hash: str, params: Dict, result: Any):
        """设置模型调用结果缓存"""
        key = self._generate_key("model", model=model, input=input_hash, params=params)
        self.model_cache[key] = result
        logger.debug(f"模型缓存设置: {key}")
    
    async def invalidate_session_cache(self, session_id: str):
        """使会话相关缓存失效"""
        keys_to_remove = []
        
        # 清除分析缓存
        for key in self.analysis_cache.keys():
            if f"session_id:{session_id}" in key:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            try:
                del self.analysis_cache[key]
                self.stats["evictions"] += 1
                logger.debug(f"缓存失效: {key}")
            except KeyError:
                pass
    
    async def clear_cache(self, cache_type: str = "all"):
        """清除缓存"""
        if cache_type == "all" or cache_type == "analysis":
            self.analysis_cache.clear()
        
        if cache_type == "all" or cache_type == "api":
            self.api_cache.clear()
        
        if cache_type == "all" or cache_type == "model":
            self.model_cache.clear()
        
        logger.info(f"缓存已清除: {cache_type}")
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests) if total_requests > 0 else 0
        
        return {
            "stats": self.stats.copy(),
            "hit_rate": hit_rate,
            "cache_sizes": {
                "analysis": len(self.analysis_cache),
                "api": len(self.api_cache),
                "model": len(self.model_cache)
            },
            "cache_limits": {
                "analysis": self.analysis_cache.maxsize,
                "api": self.api_cache.maxsize,
                "model": self.model_cache.maxsize
            }
        }
    
    async def cleanup_expired(self):
        """清理过期缓存 - TTL缓存会自动清理"""
        # TTLCache和LRUCache会自动管理过期和大小限制
        # 这个方法主要用于手动触发清理和统计
        initial_sizes = {
            "analysis": len(self.analysis_cache),
            "model": len(self.model_cache)
        }
        
        # 强制检查过期项
        _ = list(self.analysis_cache.keys())
        _ = list(self.model_cache.keys())
        
        final_sizes = {
            "analysis": len(self.analysis_cache),
            "model": len(self.model_cache)
        }
        
        removed = {
            cache: initial_sizes[cache] - final_sizes[cache]
            for cache in initial_sizes
        }
        
        if sum(removed.values()) > 0:
            logger.info(f"清理过期缓存: {removed}")
        
        return removed

# 全局缓存服务实例
_cache_service = None

def get_cache_service() -> CacheService:
    """获取缓存服务单例"""
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service
