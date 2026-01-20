"""请求重放验证工具"""
import httpx
from typing import List, Dict, Any
import json

class ReplayValidator:
    """重放验证器"""

    async def replay_requests(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量重放请求并验证"""
        results = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for req in requests:
                result = await self._replay_single(client, req)
                results.append(result)

        return {
            "total": len(results),
            "success": sum(1 for r in results if r["status"] == "success"),
            "failed": sum(1 for r in results if r["status"] == "failed"),
            "results": results
        }

    async def _replay_single(self, client: httpx.AsyncClient, req: Dict[str, Any]) -> Dict[str, Any]:
        """重放单个请求"""
        try:
            response = await client.request(
                method=req.get("method", "GET"),
                url=req["url"],
                headers=req.get("headers", {}),
                data=req.get("request_body"),
                params=req.get("params")
            )

            original_response = req.get("response", {})
            diff = self._compare_responses(original_response, {
                "status_code": response.status_code,
                "body": response.text
            })

            return {
                "request_id": req.get("id"),
                "url": req["url"],
                "status": "success" if diff["match"] else "failed",
                "diff": diff,
                "failure_reason": self._identify_failure(diff) if not diff["match"] else None
            }
        except Exception as e:
            return {
                "request_id": req.get("id"),
                "url": req["url"],
                "status": "failed",
                "error": str(e),
                "failure_reason": self._classify_error(str(e))
            }

    def _compare_responses(self, original: Dict, replayed: Dict) -> Dict[str, Any]:
        """对比响应差异"""
        status_match = original.get("status_code") == replayed.get("status_code")

        body_match = True
        if original.get("body") and replayed.get("body"):
            body_match = original["body"] == replayed["body"]

        return {
            "match": status_match and body_match,
            "status_code_match": status_match,
            "body_match": body_match,
            "original_status": original.get("status_code"),
            "replayed_status": replayed.get("status_code")
        }

    def _identify_failure(self, diff: Dict) -> str:
        """识别失败原因"""
        if not diff["status_code_match"]:
            status = diff.get("replayed_status")
            if status == 401:
                return "token_expired"
            elif status == 403:
                return "signature_error"
            elif status == 400:
                return "parameter_missing"
        return "unknown"

    def _classify_error(self, error: str) -> str:
        """分类错误"""
        if "timeout" in error.lower():
            return "timeout"
        elif "connection" in error.lower():
            return "connection_error"
        return "unknown_error"
