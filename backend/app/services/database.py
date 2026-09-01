import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from math import isfinite
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "qr_scan_results")
DYNAMODB_ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL") or None
DYNAMODB_ENABLED = os.getenv("DYNAMODB_ENABLED", "false").lower() == "true"
SCAN_RESULT_TTL_DAYS = int(os.getenv("SCAN_RESULT_TTL_DAYS", "90"))
DEFAULT_SCAN_SOURCE = os.getenv("DEFAULT_SCAN_SOURCE", "mobile_app")
DATABASE_ERROR = "DATABASE_ERROR"


def _get_table():
    """DynamoDB 테이블 객체를 생성합니다."""
    resource_kwargs = {
        "region_name": AWS_REGION,
    }

    if DYNAMODB_ENDPOINT_URL:
        resource_kwargs["endpoint_url"] = DYNAMODB_ENDPOINT_URL

    dynamodb = boto3.resource("dynamodb", **resource_kwargs)
    return dynamodb.Table(DYNAMODB_TABLE_NAME)


def _to_json_safe(value: Any) -> Any:
    """DynamoDB Decimal 등을 FastAPI JSON 응답에 안전한 타입으로 변환합니다."""
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, list):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_json_safe(item) for key, item in value.items()}
    return value


def _to_dynamodb_safe(value: Any) -> Any:
    """Recursively convert Python floats into DynamoDB-compatible Decimals."""
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("DynamoDB에 유한하지 않은 실수는 저장할 수 없습니다.")
        return Decimal(str(value))
    if isinstance(value, list):
        return [_to_dynamodb_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_dynamodb_safe(item) for key, item in value.items()}
    return value


def _make_dashboard_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """대시보드가 바로 쓰기 쉬운 핵심 필드 중심으로 정리합니다."""
    safe_item = _to_json_safe(item)
    raw_result = safe_item.get("raw_result") or {}
    vt = raw_result.get("virustotal") or {}
    stats = vt.get("stats") or {}
    analysis_flags = (
        safe_item.get("analysis_flags")
        or raw_result.get("analysis_flags")
        or {}
    )

    return {
        "scan_id": safe_item.get("scan_id"),
        "qr_type": safe_item.get("qr_type") or raw_result.get("qr_type"),
        "contains_url": safe_item.get("contains_url", analysis_flags.get("contains_url", False)),
        "url_count": safe_item.get("url_count"),
        "text_score": safe_item.get("text_score"),
        "embedded_url_count": safe_item.get("embedded_url_count", 0),
        "analyzed_embedded_url_count": safe_item.get("analyzed_embedded_url_count", 0),
        "embedded_url_max_score": safe_item.get("embedded_url_max_score"),
        "url": safe_item.get("url"),
        "domain": safe_item.get("domain") or raw_result.get("domain"),
        "local_score": safe_item.get("local_score"),
        "vt_score_delta": safe_item.get("vt_score_delta"),
        "final_score": safe_item.get("final_score", safe_item.get("risk_score", 0)),
        "risk_score": safe_item.get("risk_score", 0),
        "ruleset_version": safe_item.get("ruleset_version"),
        "status": safe_item.get("status", "unknown"),
        "message": safe_item.get("message", ""),
        "reasons": safe_item.get("reasons", []),
        "created_at": safe_item.get("created_at"),
        "date": safe_item.get("date"),
        "source": safe_item.get("source", DEFAULT_SCAN_SOURCE),
        "history_event_type": safe_item.get("history_event_type"),
        "vt_available": safe_item.get("vt_available", vt.get("available", False)),
        "vt_source": safe_item.get("vt_source", vt.get("source")),
        "vt_malicious": safe_item.get("vt_malicious", int(stats.get("malicious", 0) or 0)),
        "vt_suspicious": safe_item.get("vt_suspicious", int(stats.get("suspicious", 0) or 0)),
        "vt_harmless": safe_item.get("vt_harmless", int(stats.get("harmless", 0) or 0)),
        "vt_undetected": safe_item.get("vt_undetected", int(stats.get("undetected", 0) or 0)),
        "analysis_flags": analysis_flags,
        "cache_hit": bool(safe_item.get("cache_hit", False)),
        "cache_age_seconds": safe_item.get("cache_age_seconds"),
        "cache_revalidated": bool(safe_item.get("cache_revalidated", False)),
        "revalidation_reason": safe_item.get("revalidation_reason"),
    }


def save_scan_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    URL 분석 결과를 DynamoDB에 저장합니다.

    저장 실패가 API 전체 실패로 이어지지 않도록, 성공/실패 정보를 dict로 반환합니다.
    """
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    date = now.date().isoformat()
    expires_at = int((now + timedelta(days=SCAN_RESULT_TTL_DAYS)).timestamp())

    item = {
        "scan_id": scan_id,
        "created_at": created_at,
        "date": date,
        "expires_at": expires_at,
        "source": result.get("source", DEFAULT_SCAN_SOURCE),
        "history_event_type": result.get("history_event_type"),
        "qr_type": result.get("qr_type"),
        "contains_url": bool(result.get("contains_url", False)),
        "url_count": len(result.get("extracted_urls") or []),
        "text_score": result.get("text_score"),
        "embedded_url_count": int(result.get("embedded_url_count", 0) or 0),
        "analyzed_embedded_url_count": int(
            result.get("analyzed_embedded_url_count", 0) or 0
        ),
        "embedded_url_max_score": result.get("embedded_url_max_score"),
        "url": result.get("url", ""),
        "domain": result.get("domain", ""),
        "decoded_url": result.get("decoded_url"),
        "local_score": int(result.get("local_score", result.get("risk_score", 0))),
        "vt_score_delta": int(result.get("vt_score_delta", 0)),
        "final_score": int(result.get("final_score", result.get("risk_score", 0))),
        "risk_score": int(result.get("risk_score", 0)),
        "ruleset_version": result.get("ruleset_version"),
        "status": result.get("status", "unknown"),
        "message": result.get("message", ""),
        "reasons": result.get("reasons", []),
        "analysis_flags": result.get("analysis_flags", {}),
        "vt_available": bool(result.get("vt_available", False)),
        "vt_source": result.get("vt_source"),
        "vt_malicious": int(result.get("vt_malicious", 0)),
        "vt_suspicious": int(result.get("vt_suspicious", 0)),
        "vt_harmless": int(result.get("vt_harmless", 0)),
        "vt_undetected": int(result.get("vt_undetected", 0)),
        "cache_hit": bool(result.get("cache_hit", False)),
        "cache_age_seconds": result.get("cache_age_seconds"),
        "cache_revalidated": bool(result.get("cache_revalidated", False)),
        "revalidation_reason": result.get("revalidation_reason"),
        "raw_result": result.get("raw_result", {}),
    }

    item = {key: value for key, value in item.items() if value is not None}

    if not DYNAMODB_ENABLED:
        logger.warning("DynamoDB scan result storage is disabled")
        return {
            "saved": False,
            "scan_id": scan_id,
            "created_at": created_at,
            "date": date,
            "error": DATABASE_ERROR,
        }

    try:
        table = _get_table()
        table.put_item(Item=_to_dynamodb_safe(item))
        return {
            "saved": True,
            "scan_id": scan_id,
            "created_at": created_at,
            "date": date,
            "error": None,
        }
    except (BotoCoreError, ClientError, TypeError, ValueError):
        logger.exception("DynamoDB scan result save failed")
        return {
            "saved": False,
            "scan_id": scan_id,
            "created_at": created_at,
            "date": date,
            "error": DATABASE_ERROR,
        }


def list_scan_results(limit: int = 20, status: str | None = None) -> List[Dict[str, Any]]:
    """최근 스캔 결과를 대시보드가 쓰기 쉬운 형태로 반환합니다."""
    if not DYNAMODB_ENABLED:
        return []

    safe_limit = max(1, min(int(limit), 500))
    table = _get_table()

    scan_kwargs: Dict[str, Any] = {"Limit": safe_limit}
    if status in {"safe", "warning", "danger"}:
        scan_kwargs["FilterExpression"] = Attr("status").eq(status)

    response = table.scan(**scan_kwargs)
    items = response.get("Items", [])

    dashboard_items = [_make_dashboard_item(item) for item in items]
    return sorted(dashboard_items, key=lambda item: item.get("created_at") or "", reverse=True)


def get_scan_summary(limit: int = 200) -> Dict[str, Any]:
    """대시보드 상단 카드와 그래프용 간단 통계를 반환합니다."""
    items = list_scan_results(limit=limit)
    summary = {
        "total": len(items),
        "safe": 0,
        "warning": 0,
        "danger": 0,
        "unknown": 0,
        "vt_malicious_total": 0,
        "vt_suspicious_total": 0,
        "recent_items": items[:10],
    }

    for item in items:
        status = item.get("status", "unknown")
        if status not in {"safe", "warning", "danger"}:
            status = "unknown"
        summary[status] += 1
        summary["vt_malicious_total"] += int(item.get("vt_malicious", 0) or 0)
        summary["vt_suspicious_total"] += int(item.get("vt_suspicious", 0) or 0)

    return summary
