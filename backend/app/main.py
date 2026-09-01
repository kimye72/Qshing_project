import os
import secrets
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

from app.constants import RULESET_VERSION
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
