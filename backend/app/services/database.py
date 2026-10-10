import logging
import os
import uuid
import json
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from math import isfinite
from functools import wraps
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from app.services.analysis_budget import (
    AnalysisBudget, AnalysisBudgetExceeded, STORAGE_CALL_CAP_SECONDS,
    budget_scope, current_budget, dynamodb_config,
)

load_dotenv()

logger = logging.getLogger(__name__)

AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "qr_scan_results")
DYNAMODB_ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL") or None
DYNAMODB_ENABLED = os.getenv("DYNAMODB_ENABLED", "false").lower() == "true"
SCAN_RESULT_TTL_DAYS = int(os.getenv("SCAN_RESULT_TTL_DAYS", "90"))
DEFAULT_SCAN_SOURCE = os.getenv("DEFAULT_SCAN_SOURCE", "mobile_app")
DATABASE_ERROR = "DATABASE_ERROR"
HISTORY_READ_BUDGET_SECONDS = 8.0
HISTORY_MAX_PAGES = 20
HISTORY_MAX_EVALUATED_ITEMS = 4000
HISTORY_PAGE_EVALUATION_LIMIT = 200
_history_budget: ContextVar[AnalysisBudget | None] = ContextVar("history_read_budget", default=None)


class ScanHistoryUnavailableError(RuntimeError):
    """A disabled, failed or incomplete read must never look like an empty table."""
    def __init__(self, code: str):
        self.code = code
        super().__init__("Scan history unavailable")


def _history_read_budget(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        budget = _history_budget.get()
        if budget is None:
            outer = current_budget()
            budget = AnalysisBudget(
                seconds=HISTORY_READ_BUDGET_SECONDS, clock=outer.clock if outer else None,
            )
            if outer:
                budget.deadline = min(budget.deadline, outer.deadline)
        token = _history_budget.set(budget)
        try:
            with budget_scope(budget):
                if not DYNAMODB_ENABLED:
                    raise ScanHistoryUnavailableError("SCAN_HISTORY_DISABLED")
                budget.allowance(STORAGE_CALL_CAP_SECONDS, storage=True)
                result = function(*args, **kwargs)
                # Includes conversion/sort/aggregation, leaving response reserve.
                budget.allowance(STORAGE_CALL_CAP_SECONDS, storage=True)
                return result
        except ScanHistoryUnavailableError:
            raise
        except AnalysisBudgetExceeded:
            raise ScanHistoryUnavailableError("SCAN_HISTORY_INCOMPLETE") from None
        except Exception as exc:
            logger.warning("Scan history read failed: %s", type(exc).__name__)
            raise ScanHistoryUnavailableError("SCAN_HISTORY_READ_FAILED") from None
        finally:
            _history_budget.reset(token)
    return wrapped

# Explicit projections of EmbeddedUrlResult / EmbeddedUrlFailure in schemas.py.
# Never persist a whole analyzer result or raw external response as a child.
_EMBEDDED_URL_TARGET_FIELDS = (
    "original_url", "original_candidates", "analysis_url", "assumed_https",
)
_EMBEDDED_URL_RESULT_FIELDS = _EMBEDDED_URL_TARGET_FIELDS + (
    "url", "domain", "local_score", "vt_score_delta", "final_score", "risk_score",
    "status", "reasons", "analysis_flags", "ruleset_version", "vt_available",
    "vt_lookup_status", "vt_source", "vt_malicious", "vt_suspicious",
    "vt_harmless", "vt_undetected", "cache_hit", "cache_age_seconds",
    "cache_revalidated", "revalidation_reason",
)
_EMBEDDED_URL_FAILURE_FIELDS = _EMBEDDED_URL_TARGET_FIELDS + ("error_code",)
_EMBEDDED_URL_FLAG_FIELDS = frozenset({
    "decoded_changed", "non_https", "disallowed_scheme", "ip_address_host",
    "private_or_local_host", "long_url", "shortener", "userinfo_in_url",
    "suspicious_keyword_count", "low_confidence_keyword_count",
    "sql_xss_pattern_count", "suspicious_brand_domain", "punycode_hostname",
    "nonstandard_port", "explicit_port", "excessive_hostname_labels",
    "hostname_label_count", "historical_reputation_used", "analysis_budget_exhausted",
})


def _select_embedded_entries(entries: Any, fields: tuple[str, ...]) -> list | None:
    """Keep provided public fields; missing detail must not become an empty list."""
    if not isinstance(entries, list):
        return None
    selected = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        public = {field: entry[field] for field in fields if field in entry}
        if "analysis_flags" in public:
            flags = public["analysis_flags"]
            public["analysis_flags"] = {
                name: value for name, value in flags.items()
                if name in _EMBEDDED_URL_FLAG_FIELDS
                and (value is None or isinstance(value, (bool, int, float, Decimal)))
            } if isinstance(flags, dict) else None
        selected.append(public)
    return selected


def _embedded_history_details(item: Dict[str, Any]) -> Dict[str, Any]:
    """Do not infer historic completion, reputation or policy from current defaults."""
    complete = item.get("embedded_url_analysis_complete")
    return {
        "embedded_url_results": _select_embedded_entries(
            item.get("embedded_url_results"), _EMBEDDED_URL_RESULT_FIELDS,
        ),
        "embedded_url_failures": _select_embedded_entries(
            item.get("embedded_url_failures"), _EMBEDDED_URL_FAILURE_FIELDS,
        ),
        "embedded_url_analysis_complete": complete if isinstance(complete, bool) else None,
        "embedded_url_policy_version": item.get("embedded_url_policy_version"),
    }


def _get_table():
    """DynamoDB 테이블 객체를 생성합니다."""
    resource_kwargs = {
        "region_name": AWS_REGION,
        "config": dynamodb_config(storage=True),
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
    analysis_flags = safe_item.get("analysis_flags")
    if not isinstance(analysis_flags, dict):
        analysis_flags = raw_result.get("analysis_flags") or {}
    embedded_details = _embedded_history_details(safe_item)

    return {
        "scan_id": safe_item.get("scan_id"),
        "qr_type": safe_item.get("qr_type") or raw_result.get("qr_type"),
        "contains_url": safe_item.get("contains_url", analysis_flags.get("contains_url", False)),
        "contains_url_candidate": safe_item.get(
            "contains_url_candidate",
            analysis_flags.get("contains_url_candidate", False),
        ),
        "candidate_url_count": safe_item.get(
            "candidate_url_count",
            analysis_flags.get("url_candidate_count", 0),
        ),
        "sms_body_length": safe_item.get("sms_body_length"),
        "email_domain": safe_item.get("email_domain"),
        "email_body_length": safe_item.get("email_body_length"),
        "wifi_security_type": safe_item.get("wifi_security_type"),
        "wifi_hidden": safe_item.get("wifi_hidden"),
        "wifi_has_password": safe_item.get("wifi_has_password"),
        "social_engineering_categories": safe_item.get(
            "social_engineering_categories",
            [],
        ),
        "social_engineering_category_count": safe_item.get(
            "social_engineering_category_count",
            analysis_flags.get("social_engineering_category_count", 0),
        ),
        "url_count": safe_item.get("url_count"),
        "text_score": safe_item.get("text_score"),
        "embedded_url_count": safe_item.get("embedded_url_count", 0),
        "analyzed_embedded_url_count": safe_item.get("analyzed_embedded_url_count", 0),
        "embedded_url_max_score": safe_item.get("embedded_url_max_score"),
        **embedded_details,
        "embedded_url_details_available": (
            embedded_details["embedded_url_results"] is not None
            and embedded_details["embedded_url_failures"] is not None
        ),
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
        "vt_lookup_status": safe_item.get("vt_lookup_status", vt.get("lookup_status")),
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

    structured_content = result.get("structured_content") or {}
    item = {
        "scan_id": scan_id,
        "created_at": created_at,
        "date": date,
        "expires_at": expires_at,
        "source": result.get("source", DEFAULT_SCAN_SOURCE),
        "history_event_type": result.get("history_event_type"),
        "qr_type": result.get("qr_type"),
        "contains_url": bool(result.get("contains_url", False)),
        "contains_url_candidate": bool(
            result.get("contains_url_candidate", False)
        ),
        "candidate_url_count": int(result.get("candidate_url_count", 0) or 0),
        "sms_body_length": structured_content.get("sms_body_length"),
        "email_domain": structured_content.get("email_domain"),
        "email_body_length": structured_content.get("email_body_length"),
        "wifi_security_type": structured_content.get("wifi_security_type"),
        "wifi_hidden": structured_content.get("wifi_hidden"),
        "wifi_has_password": structured_content.get("wifi_has_password"),
        "social_engineering_categories": result.get(
            "social_engineering_categories",
            [],
        ),
        "social_engineering_category_count": int(
            result.get("social_engineering_category_count", 0) or 0
        ),
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
        "vt_lookup_status": result.get("vt_lookup_status"),
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
    item.update(_embedded_history_details(result))

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
    except (BotoCoreError, ClientError, TypeError, ValueError, AnalysisBudgetExceeded):
        logger.exception("DynamoDB scan result save failed")
        return {
            "saved": False,
            "scan_id": scan_id,
            "created_at": created_at,
            "date": date,
            "error": DATABASE_ERROR,
        }


def _created_at_order(item: Dict[str, Any]) -> datetime:
    """Never invent chronological positions for undated or invalid histories."""
    try:
        value = datetime.fromisoformat(item.get("created_at") or "")
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                else value.astimezone(timezone.utc))
    except (TypeError, ValueError, OverflowError):
        raise ScanHistoryUnavailableError("SCAN_HISTORY_INCOMPLETE") from None


def _history_identity(item: Dict[str, Any]) -> str:
    if isinstance(item.get("scan_id"), str) and item["scan_id"]:
        return "scan_id:" + item["scan_id"]
    # Old malformed records without an ID have no better identity. Preserve
    # distinct raw records and deduplicate exact copies deterministically.
    return "legacy:" + json.dumps(_to_json_safe(item), sort_keys=True, separators=(",", ":"))


@_history_read_budget
def get_recent_scan_history(limit: int = 20, status: str | None = None) -> Dict[str, Any]:
    """Finish a bounded full table traversal before claiming the latest N rows."""
    safe_limit = max(1, min(int(limit), 500))
    status_filter = status if status in {"safe", "warning", "danger"} else None
    items_by_id: Dict[str, Dict[str, Any]] = {}
    seen_keys: set[str] = set()
    next_key = None
    pages = evaluated = 0
    budget = _history_budget.get()

    while True:
        if pages >= HISTORY_MAX_PAGES or evaluated >= HISTORY_MAX_EVALUATED_ITEMS:
            raise ScanHistoryUnavailableError("SCAN_HISTORY_INCOMPLETE")
        budget.allowance(STORAGE_CALL_CAP_SECONDS, storage=True)
        page_limit = min(HISTORY_PAGE_EVALUATION_LIMIT, HISTORY_MAX_EVALUATED_ITEMS - evaluated)
        scan_kwargs: Dict[str, Any] = {"Limit": page_limit, "ConsistentRead": True}
        if status_filter:
            scan_kwargs["FilterExpression"] = Attr("status").eq(status_filter)
        if next_key:
            scan_kwargs["ExclusiveStartKey"] = next_key
        # Recreate the SDK resource so each page's socket timeouts are capped
        # by the SAME deadline's remaining allowance. Resource/credential
        # construction itself is not cancelled by a socket timeout.
        table = _get_table()
        budget.allowance(STORAGE_CALL_CAP_SECONDS, storage=True)
        response = table.scan(**scan_kwargs)
        budget.allowance(STORAGE_CALL_CAP_SECONDS, storage=True)
        page_items = response["Items"]
        scanned = response["ScannedCount"]
        if (not isinstance(page_items, list) or isinstance(scanned, bool)
                or not isinstance(scanned, (int, Decimal)) or int(scanned) != scanned
                or not len(page_items) <= scanned <= page_limit):
            raise ValueError("Invalid scan page")
        pages += 1
        evaluated += int(scanned)
        for item in page_items:
            if not isinstance(item, dict):
                raise ValueError("Invalid history item")
            if status_filter and item.get("status") != status_filter:
                continue
            identity = _history_identity(item)
            if identity in items_by_id and items_by_id[identity] != item:
                # Conflicting copies during a concurrent write cannot be
                # resolved into a trustworthy latest view; discard the read.
                raise ScanHistoryUnavailableError("SCAN_HISTORY_INCOMPLETE")
            items_by_id[identity] = item
        next_key = response.get("LastEvaluatedKey")
        if next_key is not None and not isinstance(next_key, dict):
            raise ValueError("Invalid scan cursor")
        if not next_key:
            break
        key_token = repr(sorted(next_key.items()))
        if key_token in seen_keys:
            raise ScanHistoryUnavailableError("SCAN_HISTORY_INCOMPLETE")
        seen_keys.add(key_token)

    ordered = sorted(items_by_id.values(), key=lambda item: (
        _created_at_order(item), _history_identity(item),
    ), reverse=True)
    dashboard_items = [_make_dashboard_item(item) for item in ordered[:safe_limit]]
    return {
        "items": dashboard_items,
        "metadata": {
            "scope": "latest_saved_history_for_status" if status_filter else "latest_saved_history",
            "count_unit": "stored_history_records", "requested_limit": safe_limit,
            "returned_count": len(dashboard_items), "status_filter": status_filter,
            "query_complete": True, "pages_read": pages, "evaluated_items": evaluated,
            "matching_records_count": len(items_by_id),
            "ordering": "created_at_desc_scan_id_desc",
            "read_consistency": "strong_per_item_not_snapshot",
            "bounds": {
                "time_budget_seconds": HISTORY_READ_BUDGET_SECONDS,
                "max_pages": HISTORY_MAX_PAGES,
                "max_evaluated_items": HISTORY_MAX_EVALUATED_ITEMS,
                "page_evaluation_limit": HISTORY_PAGE_EVALUATION_LIMIT,
            },
        },
    }


def list_scan_results(limit: int = 20, status: str | None = None) -> List[Dict[str, Any]]:
    """Compatibility wrapper; never return a partial read or disabled-DB empty list."""
    return get_recent_scan_history(limit=limit, status=status)["items"]


@_history_read_budget
def get_scan_summary(limit: int = 200) -> Dict[str, Any]:
    """Aggregate the latest N stored parent histories, not scans or the whole table."""
    history = get_recent_scan_history(limit=limit)
    items = history["items"]
    summary = {
        "total": len(items),
        "safe": 0,
        "warning": 0,
        "danger": 0,
        "unknown": 0,
        "vt_malicious_total": 0,
        "vt_suspicious_total": 0,
        "recent_items": items[:10],
        "metadata": {
            **history["metadata"], "aggregated_count": len(items),
            "vt_totals_scope": "parent_history_records", "recent_items_limit": 10,
        },
    }

    for item in items:
        status = item.get("status", "unknown")
        if status not in {"safe", "warning", "danger"}:
            status = "unknown"
        summary[status] += 1
        summary["vt_malicious_total"] += int(item.get("vt_malicious", 0) or 0)
        summary["vt_suspicious_total"] += int(item.get("vt_suspicious", 0) or 0)

    return summary
