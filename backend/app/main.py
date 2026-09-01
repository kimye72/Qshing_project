import os
import secrets
import logging
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

from app.constants import MAX_EMBEDDED_URLS_ANALYZED, RULESET_VERSION
from app.schemas import (
    QRAnalyzeRequest,
    QRAnalyzeResponse,
    ScanRequest,
    ScanResponse,
)
from app.services.database import (
    DATABASE_ERROR,
    get_scan_summary,
    list_scan_results,
    save_scan_result,
)
from app.services.qr_analyzer import analyze_non_url_qr, decode_repeatedly
from app.services.scanner import analyze_url
from app.services.url_cache import analyze_url_with_cache


APP_VERSION = "0.4.0"
HTTP_URL_PREFIXES = ("http://", "https://")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
logger = logging.getLogger(__name__)


app = FastAPI(
    title="QR 피싱 예방 시스템 API",
    description=(
        "QR 코드에 포함된 URL 및 비URL 콘텐츠를 분석하여 "
        "피싱 위험 점수, 상태 및 판단 근거를 제공하는 백엔드 API입니다."
    ),
    version=APP_VERSION,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def attach_db_result(result: dict, db_result: dict) -> dict:
    """
    QR 분석 결과에 DynamoDB 저장 결과를 추가합니다.
    기존 database.py와 이후 고도화 버전의 반환 형식을 모두 지원합니다.
    """

    result["scan_id"] = db_result.get("scan_id")
    result["created_at"] = db_result.get("created_at")
    result["date"] = db_result.get("date")

    db_saved = db_result.get(
        "db_saved",
        db_result.get("saved", False),
    )
    result["db_saved"] = db_saved

    db_error = db_result.get(
        "db_error",
        db_result.get("error"),
    )
    result["db_error"] = (
        DATABASE_ERROR
        if not db_saved and db_error is not None
        else None
    )

    return result


def require_admin_api_key(
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> None:
    """Fail closed unless the configured administrator key matches."""
    if not ADMIN_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="관리자 API를 사용할 수 없습니다.",
        )

    if x_admin_key is None:
        raise HTTPException(
            status_code=401,
            detail="관리자 인증이 필요합니다.",
        )

    if not secrets.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(
            status_code=403,
            detail="관리자 인증에 실패했습니다.",
        )


def ensure_analysis_contract(result: dict) -> dict:
    """Add common metadata without changing an analyzer's existing decision."""
    risk_score = int(result.get("risk_score", 0))
    result.setdefault("local_score", risk_score)
    result.setdefault("vt_score_delta", 0)
    result["final_score"] = risk_score
    result.setdefault("ruleset_version", RULESET_VERSION)
    result.setdefault("vt_available", False)
    result.setdefault("vt_source", None)
    result.setdefault("vt_malicious", 0)
    result.setdefault("vt_suspicious", 0)
    result.setdefault("vt_harmless", 0)
    result.setdefault("vt_undetected", 0)
    result.setdefault("cache_hit", False)
    result.setdefault("cache_age_seconds", None)
    result.setdefault("cache_revalidated", False)
    result.setdefault("revalidation_reason", None)
    return result


def persist_scan_history(result: dict) -> dict:
    """Persist only history-worthy URL events while preserving non-URL behavior."""
    history_policy_applies = (
        "_history_should_save" in result
        or "_history_event_type" in result
    )
    should_save = bool(result.pop("_history_should_save", True))
    event_type = result.pop("_history_event_type", None)

    result["history_saved"] = None
    result["history_event_type"] = None
    result["history_skip_reason"] = None

    if not should_save:
        result["history_saved"] = False
        result["history_skip_reason"] = "duplicate_unchanged"
        return attach_db_result(
            result,
            {
                "saved": False,
                "scan_id": None,
                "created_at": None,
                "date": None,
                "error": None,
            },
        )

    history_result = dict(result)
    if event_type:
        history_result["history_event_type"] = event_type

    persisted_result = attach_db_result(
        result,
        save_scan_result(history_result),
    )
    if history_policy_applies:
        persisted_result["history_saved"] = bool(persisted_result["db_saved"])
        persisted_result["history_event_type"] = event_type

    return persisted_result


def resolve_direct_http_url(content: str) -> str | None:
    """Return a validated direct HTTP(S) URL, including an encoded full URL."""
    try:
        decoded_content = decode_repeatedly(content, max_rounds=3)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="QR 콘텐츠를 URL 디코딩할 수 없습니다.",
        ) from None

    if content.lower().startswith(HTTP_URL_PREFIXES):
        analysis_url = content
    elif decoded_content.lower().startswith(HTTP_URL_PREFIXES):
        analysis_url = decoded_content
    else:
        return None

    try:
        parsed = urlparse(analysis_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        _ = parsed.port
    except (ValueError, UnicodeError):
        raise HTTPException(
            status_code=400,
            detail="유효하지 않은 HTTP(S) URL입니다.",
        ) from None

    if scheme not in {"http", "https"} or not hostname:
        raise HTTPException(
            status_code=400,
            detail="유효하지 않은 HTTP(S) URL입니다.",
        )

    return analysis_url


def _status_and_message_for_qr(risk_score: int) -> tuple[str, str]:
    if risk_score >= 70:
        return (
            "danger",
            "위험 가능성이 높은 QR입니다. 자동 실행하거나 안내된 행동을 바로 수행하지 마세요.",
        )
    if risk_score >= 30:
        return (
            "warning",
            "주의가 필요한 QR입니다. 포함된 연락처, 계좌, 인증번호 요청 등을 반드시 확인하세요.",
        )
    return (
        "safe",
        "URL이 아닌 QR입니다. 현재 기준으로는 높은 위험 요소가 발견되지 않았습니다.",
    )


def _embedded_url_response(result: dict, analysis_url: str) -> dict:
    return {
        "url": result.get("url", analysis_url),
        "domain": result.get("domain"),
        "local_score": int(result.get("local_score", result.get("risk_score", 0))),
        "vt_score_delta": int(result.get("vt_score_delta", 0)),
        "final_score": int(result.get("final_score", result.get("risk_score", 0))),
        "risk_score": int(result.get("risk_score", result.get("final_score", 0))),
        "status": result.get("status", "safe"),
        "reasons": list(result.get("reasons") or []),
        "analysis_flags": dict(result.get("analysis_flags") or {}),
        "ruleset_version": result.get("ruleset_version", RULESET_VERSION),
        "vt_available": bool(result.get("vt_available", False)),
        "vt_source": result.get("vt_source"),
        "vt_malicious": int(result.get("vt_malicious", 0) or 0),
        "vt_suspicious": int(result.get("vt_suspicious", 0) or 0),
        "vt_harmless": int(result.get("vt_harmless", 0) or 0),
        "vt_undetected": int(result.get("vt_undetected", 0) or 0),
        "cache_hit": bool(result.get("cache_hit", False)),
        "cache_age_seconds": result.get("cache_age_seconds"),
        "cache_revalidated": bool(result.get("cache_revalidated", False)),
        "revalidation_reason": result.get("revalidation_reason"),
    }


def analyze_text_with_embedded_urls(result: dict) -> dict:
    """Combine existing text risk with up to three distinct embedded URL results."""
    extracted_urls = list(result.get("extracted_urls") or [])
    unique_urls = list(dict.fromkeys(extracted_urls))
    embedded_results: list[dict] = []

    for extracted_url in unique_urls[:MAX_EMBEDDED_URLS_ANALYZED]:
        try:
            analysis_url = resolve_direct_http_url(extracted_url)
            if analysis_url is None:
                continue
            url_result = analyze_url_with_cache(
                analysis_url,
                analyzer=analyze_url,
                analysis_context="embedded",
            )
            url_result = ensure_analysis_contract(url_result)
            embedded_results.append(
                _embedded_url_response(url_result, analysis_url)
            )
        except Exception as exc:
            logger.warning(
                "Embedded URL analysis failed: %s",
                type(exc).__name__,
            )

    text_score = int(result.get("risk_score", 0))
    embedded_scores = [item["final_score"] for item in embedded_results]
    embedded_url_max_score = max(embedded_scores) if embedded_scores else None
    final_score = max(text_score, embedded_url_max_score or 0)
    status, message = _status_and_message_for_qr(final_score)

    reasons = list(result.get("reasons") or [])
    if embedded_results:
        pending_reason = "일반 텍스트 안에 URL이 포함되어 있습니다. 포함된 URL 분석이 필요합니다."
        completed_reason = "일반 텍스트 안에 URL이 포함되어 있어 포함 URL 분석을 수행했습니다."
        reasons = [
            completed_reason if reason == pending_reason else reason
            for reason in reasons
        ]
    high_risk_count = sum(
        item["status"] == "danger" for item in embedded_results
    )
    if high_risk_count:
        reasons.append("포함된 URL 분석에서 높은 위험도가 탐지되었습니다.")
    elif embedded_url_max_score is not None and embedded_url_max_score >= 30:
        reasons.append("포함된 URL 분석에서 주의가 필요한 위험도가 탐지되었습니다.")

    analysis_flags = dict(result.get("analysis_flags") or {})
    analysis_flags.update(
        {
            "embedded_url_analyzed": bool(embedded_results),
            "embedded_url_count": len(unique_urls),
            "analyzed_embedded_url_count": len(embedded_results),
            "embedded_url_high_risk_count": high_risk_count,
        }
    )

    result.update(
        {
            "text_score": text_score,
            "embedded_url_count": len(unique_urls),
            "analyzed_embedded_url_count": len(embedded_results),
            "embedded_url_max_score": embedded_url_max_score,
            "embedded_url_results": embedded_results,
            "local_score": text_score,
            "vt_score_delta": 0,
            "final_score": final_score,
            "risk_score": final_score,
            "status": status,
            "message": message,
            "reasons": reasons,
            "analysis_flags": analysis_flags,
        }
    )
    return result


@app.get(
    "/",
    summary="서버 상태 확인",
    description="QR 피싱 예방 시스템 백엔드가 정상적으로 실행 중인지 확인합니다.",
    tags=["System"],
)
def root():
    return {
        "message": "QR 피싱 예방앱 백엔드가 정상 실행 중입니다.",
        "version": APP_VERSION,
    }


@app.post(
    "/scan",
    response_model=ScanResponse,
    summary="URL 분석 및 저장",
    description=(
        "전달받은 URL의 구조와 외부 평판 정보를 분석하고, "
        "분석 결과를 DynamoDB에 저장한 뒤 위험 판단 결과를 반환합니다."
    ),
    tags=["Analysis"],
)
def scan_url(data: ScanRequest):
    result = ensure_analysis_contract(
        analyze_url_with_cache(str(data.url), analyzer=analyze_url)
    )

    return persist_scan_history(result)


@app.post(
    "/analyze-qr",
    response_model=QRAnalyzeResponse,
    summary="QR 내용 통합 분석",
    description=(
        "QR 코드에서 추출한 원본 콘텐츠를 분석합니다. "
        "URL 콘텐츠는 URL 분석을 수행하고, "
        "비URL 콘텐츠는 유형과 포함 정보를 기반으로 위험도를 분석합니다."
    ),
    tags=["Analysis"],
)
def analyze_qr(data: QRAnalyzeRequest):
    content = data.content.strip()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="QR 콘텐츠는 공백일 수 없습니다.",
        )

    analysis_url = resolve_direct_http_url(content)

    if analysis_url is not None:
        result = analyze_url_with_cache(analysis_url, analyzer=analyze_url)

        result["qr_type"] = "url"
        result["raw_content_preview"] = (
            content[:200]
            + ("..." if len(content) > 200 else "")
        )
        result["contains_url"] = True
        result["extracted_urls"] = [
            result.get("url", analysis_url)
        ]

    else:
        result = analyze_non_url_qr(content)
        if result.get("qr_type") == "text_with_url":
            result = analyze_text_with_embedded_urls(result)

    result = ensure_analysis_contract(result)
    return persist_scan_history(result)


@app.get(
    "/scans",
    dependencies=[Depends(require_admin_api_key)],
    summary="스캔 결과 목록 조회",
    description=(
        "DynamoDB에 저장된 최근 QR 분석 이력을 조회합니다. "
        "직접 URL은 최초 분석과 위험도 변화 이력 중심이며, "
        "위험 상태를 기준으로 결과를 필터링할 수 있습니다."
    ),
    tags=["Dashboard"],
)
def get_scans(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="조회할 최대 결과 개수",
    ),
    status: Literal["safe", "warning", "danger"] | None = Query(
        default=None,
        description="위험 상태 필터",
    ),
):
    return {
        "items": list_scan_results(
            limit=limit,
            status=status,
        )
    }


@app.get(
    "/scans/summary",
    dependencies=[Depends(require_admin_api_key)],
    summary="스캔 통계 조회",
    description=(
        "저장된 QR 분석 이력을 기반으로 "
        "위험 상태별 통계 정보를 반환합니다."
    ),
    tags=["Dashboard"],
)
def get_scans_summary(
    limit: int = Query(
        default=200,
        ge=1,
        le=500,
        description="통계 계산에 사용할 최대 결과 개수",
    )
):
    return get_scan_summary(limit=limit)


handler = Mangum(app)
