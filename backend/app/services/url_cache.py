import hashlib
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal

import boto3
from dotenv import load_dotenv

from app.constants import RULESET_VERSION
from app.services import virustotal
from app.services.database import (
    AWS_REGION,
    DYNAMODB_ENDPOINT_URL,
    _to_dynamodb_safe,
    _to_json_safe,
)
from app.services.scanner import (
    _decode_repeatedly,
    analyze_url,
    analyze_url_with_vt_result,
)


load_dotenv()

logger = logging.getLogger(__name__)

URL_CACHE_ENABLED = os.getenv("URL_CACHE_ENABLED", "false").lower() == "true"
URL_CACHE_TABLE_NAME = os.getenv(
    "URL_CACHE_TABLE_NAME",
    "qr_url_analysis_cache",
)


def _read_non_negative_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


URL_CACHE_FRESHNESS_SECONDS = _read_non_negative_int(
    "URL_CACHE_FRESHNESS_SECONDS",
    86400,
)

_CACHE_RESULT_FIELDS = (
    "domain",
    "local_score",
    "vt_score_delta",
    "final_score",
    "risk_score",
    "status",
    "message",
    "reasons",
    "analysis_flags",
    "ruleset_version",
    "vt_available",
    "vt_source",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
)
_REQUIRED_CACHE_FIELDS = {
    "url_hash",
    "domain",
    "local_score",
    "vt_score_delta",
    "final_score",
    "risk_score",
    "status",
    "message",
    "reasons",
    "analysis_flags",
    "ruleset_version",
    "last_checked_at",
}


def _get_cache_table():
    resource_kwargs = {"region_name": AWS_REGION}
    if DYNAMODB_ENDPOINT_URL:
        resource_kwargs["endpoint_url"] = DYNAMODB_ENDPOINT_URL

    dynamodb = boto3.resource("dynamodb", **resource_kwargs)
    return dynamodb.Table(URL_CACHE_TABLE_NAME)


def build_url_hash(url: str) -> str:
    """Hash the exact URL string passed to the URL analyzer."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _utc_epoch_seconds() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _as_epoch_seconds(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def get_cache_age_seconds(
    cache_item: dict[str, Any],
    *,
    now_epoch: int | None = None,
) -> int | None:
    checked_at = _as_epoch_seconds(cache_item.get("last_checked_at"))
    if checked_at is None:
        return None

    now = _utc_epoch_seconds() if now_epoch is None else int(now_epoch)
    return max(0, now - checked_at)


def is_cache_fresh(
    cache_item: dict[str, Any],
    *,
    now_epoch: int | None = None,
) -> bool:
    age = get_cache_age_seconds(cache_item, now_epoch=now_epoch)
    return age is not None and age <= URL_CACHE_FRESHNESS_SECONDS


def get_cached_url_analysis(url: str) -> dict[str, Any] | None:
    if not URL_CACHE_ENABLED:
        return None

    response = _get_cache_table().get_item(
        Key={"url_hash": build_url_hash(url)},
        ConsistentRead=True,
    )
    item = response.get("Item")
    return _to_json_safe(item) if item else None


def _risk_changed(previous: dict[str, Any] | None, result: dict[str, Any]) -> bool:
    if not previous:
        return False
    return (
        int(previous.get("final_score", previous.get("risk_score", 0)))
        != int(result.get("final_score", result.get("risk_score", 0)))
        or previous.get("status") != result.get("status")
    )


def save_cached_url_analysis(
    url: str,
    result: dict[str, Any],
    *,
    now_epoch: int | None = None,
    last_checked_at: int | None = None,
    vt_checked_at: int | None = None,
    previous_item: dict[str, Any] | None = None,
    increment_scan: bool = False,
    direct_history_initialized: bool | None = None,
) -> None:
    now = _utc_epoch_seconds() if now_epoch is None else int(now_epoch)
    checked_at = now if last_checked_at is None else int(last_checked_at)

    analysis_values = {
        "domain": result.get("domain", ""),
        "local_score": int(result.get("local_score", result.get("risk_score", 0))),
        "vt_score_delta": int(result.get("vt_score_delta", 0)),
        "final_score": int(result.get("final_score", result.get("risk_score", 0))),
        "risk_score": int(result.get("risk_score", 0)),
        "status": result.get("status"),
        "message": result.get("message", ""),
        "reasons": result.get("reasons", []),
        "analysis_flags": result.get("analysis_flags", {}),
        "ruleset_version": result.get("ruleset_version", RULESET_VERSION),
        "vt_available": bool(result.get("vt_available", False)),
        "vt_source": result.get("vt_source"),
        "vt_malicious": int(result.get("vt_malicious", 0) or 0),
        "vt_suspicious": int(result.get("vt_suspicious", 0) or 0),
        "vt_harmless": int(result.get("vt_harmless", 0) or 0),
        "vt_undetected": int(result.get("vt_undetected", 0) or 0),
        "analyzed_at": now,
        "last_checked_at": checked_at,
    }

    if vt_checked_at is not None:
        analysis_values["vt_checked_at"] = int(vt_checked_at)
    if direct_history_initialized is not None:
        analysis_values["direct_history_initialized"] = bool(
            direct_history_initialized
        )

    if previous_item:
        if _risk_changed(previous_item, result):
            analysis_values["previous_score"] = int(
                previous_item.get("final_score", previous_item.get("risk_score", 0))
            )
            analysis_values["previous_status"] = previous_item.get("status")
            analysis_values["changed_at"] = now

    names: dict[str, str] = {}
    values: dict[str, Any] = {}
    assignments: list[str] = []
    removals = [
        "revalidation_deferred_reason",
        "last_revalidation_attempt_at",
    ]

    for field, value in analysis_values.items():
        if value is None:
            removals.append(field)
            continue
        name_key = f"#{field}"
        value_key = f":{field}"
        names[name_key] = field
        values[value_key] = value
        assignments.append(f"{name_key} = {value_key}")

    if increment_scan:
        names.update(
            {
                "#first_seen_at": "first_seen_at",
                "#last_scanned_at": "last_scanned_at",
                "#scan_count": "scan_count",
            }
        )
        values.update({":scan_time": now, ":one": 1})
        assignments.extend(
            [
                "#first_seen_at = if_not_exists(#first_seen_at, :scan_time)",
                "#last_scanned_at = :scan_time",
            ]
        )

    for field in removals:
        names[f"#{field}"] = field

    update_expression = "SET " + ", ".join(assignments)
    if removals:
        update_expression += " REMOVE " + ", ".join(
            f"#{field}" for field in removals
        )
    if increment_scan:
        update_expression += " ADD #scan_count :one"

    _get_cache_table().update_item(
        Key={"url_hash": build_url_hash(url)},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=_to_dynamodb_safe(values),
    )


def record_cached_url_scan(url_hash: str, *, scanned_at: int) -> None:
    """Atomically record one request for an existing URL cache item."""
    _get_cache_table().update_item(
        Key={"url_hash": url_hash},
        UpdateExpression=(
            "SET #first_seen_at = if_not_exists(#first_seen_at, :scanned_at), "
            "#last_scanned_at = :scanned_at, "
            "#direct_history_initialized = :direct_history_initialized "
            "ADD #scan_count :one"
        ),
        ExpressionAttributeNames={
            "#first_seen_at": "first_seen_at",
            "#last_scanned_at": "last_scanned_at",
            "#direct_history_initialized": "direct_history_initialized",
            "#scan_count": "scan_count",
        },
        ExpressionAttributeValues={
            ":scanned_at": int(scanned_at),
            ":direct_history_initialized": True,
            ":one": 1,
        },
    )


def update_cache_check_time(
    url_hash: str,
    *,
    checked_at: int,
    vt_checked_at: int | None = None,
) -> None:
    names = {"#last_checked_at": "last_checked_at"}
    values: dict[str, Any] = {":last_checked_at": int(checked_at)}
    assignments = ["#last_checked_at = :last_checked_at"]

    if vt_checked_at is not None:
        names["#vt_checked_at"] = "vt_checked_at"
        values[":vt_checked_at"] = int(vt_checked_at)
        assignments.append("#vt_checked_at = :vt_checked_at")

    names.update(
        {
            "#last_revalidation_attempt_at": "last_revalidation_attempt_at",
            "#revalidation_deferred_reason": "revalidation_deferred_reason",
        }
    )

    _get_cache_table().update_item(
        Key={"url_hash": url_hash},
        UpdateExpression=(
            "SET "
            + ", ".join(assignments)
            + " REMOVE #last_revalidation_attempt_at, #revalidation_deferred_reason"
        ),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=_to_dynamodb_safe(values),
    )


def _record_deferred_revalidation(url_hash: str, attempted_at: int) -> None:
    _get_cache_table().update_item(
        Key={"url_hash": url_hash},
        UpdateExpression=(
            "SET #attempted_at = :attempted_at, "
            "#deferred_reason = :deferred_reason"
        ),
        ExpressionAttributeNames={
            "#attempted_at": "last_revalidation_attempt_at",
            "#deferred_reason": "revalidation_deferred_reason",
        },
        ExpressionAttributeValues={
            ":attempted_at": int(attempted_at),
            ":deferred_reason": "virustotal_unavailable",
        },
    )


def _cache_item_is_usable(item: Any) -> bool:
    if not isinstance(item, dict) or not _REQUIRED_CACHE_FIELDS.issubset(item):
        return False
    if not isinstance(item.get("url_hash"), str):
        return False
    if _as_epoch_seconds(item.get("last_checked_at")) is None:
        return False
    if item.get("status") not in {"safe", "warning", "danger"}:
        return False
    if not isinstance(item.get("reasons"), list):
        return False
    if not isinstance(item.get("analysis_flags"), dict):
        return False
    try:
        for field in ("local_score", "vt_score_delta", "final_score", "risk_score"):
            int(item[field])
    except (TypeError, ValueError, OverflowError):
        return False
    return True


def _restore_cached_result(url: str, item: dict[str, Any]) -> dict[str, Any]:
    decoded_url, _ = _decode_repeatedly(url)
    return {
        "url": url,
        "domain": item.get("domain", ""),
        "decoded_url": decoded_url if decoded_url != url else None,
        "qr_type": "url",
        "contains_url": True,
        "extracted_urls": [url],
        "local_score": int(item.get("local_score", 0)),
        "vt_score_delta": int(item.get("vt_score_delta", 0)),
        "final_score": int(item.get("final_score", item.get("risk_score", 0))),
        "risk_score": int(item.get("risk_score", 0)),
        "ruleset_version": item.get("ruleset_version", RULESET_VERSION),
        "status": item.get("status"),
        "message": item.get("message", ""),
        "reasons": list(item.get("reasons") or []),
        "analysis_flags": dict(item.get("analysis_flags") or {}),
        "vt_available": bool(item.get("vt_available", False)),
        "vt_source": item.get("vt_source"),
        "vt_malicious": int(item.get("vt_malicious", 0) or 0),
        "vt_suspicious": int(item.get("vt_suspicious", 0) or 0),
        "vt_harmless": int(item.get("vt_harmless", 0) or 0),
        "vt_undetected": int(item.get("vt_undetected", 0) or 0),
    }


def _with_cache_metadata(
    result: dict[str, Any],
    *,
    cache_hit: bool,
    cache_age_seconds: int | None,
    cache_revalidated: bool,
    revalidation_reason: str | None,
) -> dict[str, Any]:
    enriched = dict(result)
    enriched.update(
        {
            "cache_hit": cache_hit,
            "cache_age_seconds": cache_age_seconds,
            "cache_revalidated": cache_revalidated,
            "revalidation_reason": revalidation_reason,
        }
    )
    return enriched


def _with_history_policy(
    result: dict[str, Any],
    *,
    should_save: bool,
    event_type: str | None,
) -> dict[str, Any]:
    result["_history_should_save"] = should_save
    result["_history_event_type"] = event_type
    return result


def _with_context_history_policy(
    result: dict[str, Any],
    *,
    analysis_context: Literal["direct", "embedded"],
    should_save: bool,
    event_type: str | None,
) -> dict[str, Any]:
    if analysis_context == "embedded":
        result.pop("_history_should_save", None)
        result.pop("_history_event_type", None)
        return result
    return _with_history_policy(
        result,
        should_save=should_save,
        event_type=event_type,
    )


def _cached_history_policy(
    *,
    scan_recorded: bool,
    needs_initial_history: bool,
    risk_changed: bool = False,
    ruleset_changed: bool = False,
) -> tuple[bool, str | None]:
    if not scan_recorded:
        return True, "cache_fallback"
    if needs_initial_history:
        return True, "initial_analysis"
    if risk_changed:
        return True, (
            "ruleset_reclassified" if ruleset_changed else "risk_changed"
        )
    return False, None


def _virustotal_is_configured() -> bool:
    return bool(virustotal.VIRUSTOTAL_ENABLED and virustotal.VIRUSTOTAL_API_KEY)


def _has_current_vt_report(result: dict[str, Any]) -> bool:
    return bool(
        result.get("vt_available")
        and result.get("vt_source") == "url_report"
    )


def _has_historical_vt_result(item: dict[str, Any]) -> bool:
    return bool(
        item.get("vt_available")
        or int(item.get("vt_score_delta", 0) or 0) != 0
    )


def _cached_vt_result(item: dict[str, Any]) -> dict[str, Any]:
    available = bool(item.get("vt_available") or item.get("vt_score_delta"))
    return {
        "enabled": True,
        "available": available,
        "source": item.get("vt_source"),
        "stats": {
            "malicious": int(item.get("vt_malicious", 0) or 0),
            "suspicious": int(item.get("vt_suspicious", 0) or 0),
            "harmless": int(item.get("vt_harmless", 0) or 0),
            "undetected": int(item.get("vt_undetected", 0) or 0),
        },
    }


def _analysis_fields_equal(item: dict[str, Any], result: dict[str, Any]) -> bool:
    for field in _CACHE_RESULT_FIELDS:
        cached_value = item.get(field)
        result_value = result.get(field)
        if field in {
            "local_score",
            "vt_score_delta",
            "final_score",
            "risk_score",
            "vt_malicious",
            "vt_suspicious",
            "vt_harmless",
            "vt_undetected",
        }:
            cached_value = int(cached_value or 0)
            result_value = int(result_value or 0)
        if cached_value != result_value:
            return False
    return True


def _try_save_cache(
    url: str,
    result: dict[str, Any],
    **kwargs: Any,
) -> bool:
    try:
        save_cached_url_analysis(url, result, **kwargs)
        return True
    except Exception as exc:
        logger.warning("URL cache write failed: %s", type(exc).__name__)
        return False


def _try_record_scan(url_hash: str, now_epoch: int) -> bool:
    try:
        record_cached_url_scan(url_hash, scanned_at=now_epoch)
        return True
    except Exception as exc:
        logger.warning("URL cache scan counter update failed: %s", type(exc).__name__)
        return False


def _try_record_deferred(url_hash: str, now_epoch: int) -> None:
    try:
        _record_deferred_revalidation(url_hash, now_epoch)
    except Exception as exc:
        logger.warning("URL cache metadata update failed: %s", type(exc).__name__)


def analyze_url_with_cache(
    url: str,
    *,
    analyzer: Callable[[str], dict[str, Any]] = analyze_url,
    now_epoch: int | None = None,
    analysis_context: Literal["direct", "embedded"] = "direct",
) -> dict[str, Any]:
    """Analyze a URL with an optional, failure-isolated DynamoDB cache."""
    if analysis_context not in {"direct", "embedded"}:
        raise ValueError("Unsupported URL analysis context")

    now = _utc_epoch_seconds() if now_epoch is None else int(now_epoch)
    is_direct = analysis_context == "direct"

    if not URL_CACHE_ENABLED:
        return _with_context_history_policy(
            _with_cache_metadata(
                analyzer(url),
                cache_hit=False,
                cache_age_seconds=None,
                cache_revalidated=False,
                revalidation_reason=None,
            ),
            analysis_context=analysis_context,
            should_save=True,
            event_type=None,
        )

    lookup_failed = False
    try:
        cached = get_cached_url_analysis(url)
    except Exception as exc:
        logger.warning("URL cache lookup failed: %s", type(exc).__name__)
        cached = None
        lookup_failed = True

    if not _cache_item_is_usable(cached):
        result = analyzer(url)
        vt_checked_at = now if _has_current_vt_report(result) else None
        if not lookup_failed:
            _try_save_cache(
                url,
                result,
                now_epoch=now,
                vt_checked_at=vt_checked_at,
                increment_scan=is_direct,
                direct_history_initialized=(
                    True
                    if is_direct
                    else False if cached is None else None
                ),
            )
        return _with_context_history_policy(
            _with_cache_metadata(
                result,
                cache_hit=False,
                cache_age_seconds=None,
                cache_revalidated=False,
                revalidation_reason=None if lookup_failed else "cache_miss",
            ),
            analysis_context=analysis_context,
            should_save=True,
            event_type=(
                "cache_fallback"
                if lookup_failed or cached is not None
                else "initial_analysis"
            ),
        )

    age = get_cache_age_seconds(cached, now_epoch=now)
    ruleset_matches = cached.get("ruleset_version") == RULESET_VERSION
    url_hash = cached["url_hash"]
    needs_initial_history = (
        is_direct and cached.get("direct_history_initialized") is False
    )
    scan_recorded = _try_record_scan(url_hash, now) if is_direct else True
    if ruleset_matches and is_cache_fresh(cached, now_epoch=now):
        should_save, event_type = _cached_history_policy(
            scan_recorded=scan_recorded,
            needs_initial_history=needs_initial_history,
        )
        return _with_context_history_policy(
            _with_cache_metadata(
                _restore_cached_result(url, cached),
                cache_hit=True,
                cache_age_seconds=age,
                cache_revalidated=False,
                revalidation_reason=None,
            ),
            analysis_context=analysis_context,
            should_save=should_save,
            event_type=event_type,
        )

    reason = "stale_cache" if ruleset_matches else "ruleset_changed"

    if ruleset_matches and not _virustotal_is_configured():
        _try_record_deferred(url_hash, now)
        should_save, event_type = _cached_history_policy(
            scan_recorded=scan_recorded,
            needs_initial_history=needs_initial_history,
        )
        return _with_context_history_policy(
            _with_cache_metadata(
                _restore_cached_result(url, cached),
                cache_hit=False,
                cache_age_seconds=age,
                cache_revalidated=False,
                revalidation_reason=reason,
            ),
            analysis_context=analysis_context,
            should_save=should_save,
            event_type=event_type,
        )

    result = analyzer(url)
    has_current_vt_report = _has_current_vt_report(result)

    if ruleset_matches and not has_current_vt_report:
        _try_record_deferred(url_hash, now)
        should_save, event_type = _cached_history_policy(
            scan_recorded=scan_recorded,
            needs_initial_history=needs_initial_history,
        )
        return _with_context_history_policy(
            _with_cache_metadata(
                _restore_cached_result(url, cached),
                cache_hit=False,
                cache_age_seconds=age,
                cache_revalidated=False,
                revalidation_reason=reason,
            ),
            analysis_context=analysis_context,
            should_save=should_save,
            event_type=event_type,
        )

    if not ruleset_matches and not has_current_vt_report and _has_historical_vt_result(cached):
        result = analyze_url_with_vt_result(url, _cached_vt_result(cached))
        risk_changed = _risk_changed(cached, result)
        previous_checked_at = _as_epoch_seconds(cached.get("last_checked_at")) or 0
        previous_vt_checked_at = _as_epoch_seconds(cached.get("vt_checked_at"))
        _try_save_cache(
            url,
            result,
            now_epoch=now,
            last_checked_at=previous_checked_at,
            vt_checked_at=previous_vt_checked_at,
            previous_item=cached,
        )
        should_save, event_type = _cached_history_policy(
            scan_recorded=scan_recorded,
            needs_initial_history=needs_initial_history,
            risk_changed=risk_changed,
            ruleset_changed=True,
        )
        return _with_context_history_policy(
            _with_cache_metadata(
                result,
                cache_hit=False,
                cache_age_seconds=age,
                cache_revalidated=False,
                revalidation_reason=reason,
            ),
            analysis_context=analysis_context,
            should_save=should_save,
            event_type=event_type,
        )

    risk_changed = _risk_changed(cached, result)
    if _analysis_fields_equal(cached, result):
        try:
            update_cache_check_time(
                url_hash,
                checked_at=now,
                vt_checked_at=now if has_current_vt_report else None,
            )
        except Exception as exc:
            logger.warning("URL cache freshness update failed: %s", type(exc).__name__)
    else:
        _try_save_cache(
            url,
            result,
            now_epoch=now,
            vt_checked_at=now if has_current_vt_report else None,
            previous_item=cached,
        )

    should_save, event_type = _cached_history_policy(
        scan_recorded=scan_recorded,
        needs_initial_history=needs_initial_history,
        risk_changed=risk_changed,
        ruleset_changed=not ruleset_matches,
    )
    return _with_context_history_policy(
        _with_cache_metadata(
            result,
            cache_hit=False,
            cache_age_seconds=0,
            cache_revalidated=True,
            revalidation_reason=reason,
        ),
        analysis_context=analysis_context,
        should_save=should_save,
        event_type=event_type,
    )
