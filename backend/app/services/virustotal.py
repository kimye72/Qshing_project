import base64
import os
from typing import Any

import requests
from dotenv import load_dotenv

from app.services.analysis_budget import AnalysisBudgetExceeded, VT_CALL_CAP_SECONDS, io_timeout

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() == "true"
VIRUSTOTAL_SUBMIT_IF_NOT_FOUND = os.getenv("VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", "false").lower() == "true"
VIRUSTOTAL_TIMEOUT_SECONDS = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


def make_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def _headers() -> dict[str, str]:
    return {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}


def _unavailable(status: str, message: str) -> dict[str, Any]:
    return {
        "enabled": VIRUSTOTAL_ENABLED,
        "available": False,
        "lookup_status": status,
        "error": message,
    }


def _configuration_failure():
    if not VIRUSTOTAL_ENABLED:
        return _unavailable("disabled", "외부 평판 조회를 사용하지 않았습니다.")
    if not VIRUSTOTAL_API_KEY:
        return _unavailable("lookup_failed", "외부 평판 정보를 확인하지 못했습니다.")
    return None


def _request(method, endpoint, **kwargs):
    """One attempt, no redirects/retries/polling, using the shared allowance."""
    try:
        timeout = io_timeout(min(VIRUSTOTAL_TIMEOUT_SECONDS, VT_CALL_CAP_SECONDS))
        return method(endpoint, headers=_headers(), timeout=timeout,
                      allow_redirects=False, **kwargs), None
    except AnalysisBudgetExceeded:
        return None, _unavailable("budget_exhausted", "분석 시간 안에 외부 평판 정보를 확인하지 못했습니다.")
    except requests.Timeout:
        return None, _unavailable("timeout", "외부 평판 조회 시간이 초과되었습니다.")
    except requests.RequestException:
        return None, _unavailable("lookup_failed", "외부 평판 정보를 확인하지 못했습니다.")


def _http_failure(status_code):
    if status_code == 429:
        result = _unavailable("rate_limited", "외부 평판 조회가 일시적으로 제한되었습니다.")
    else:
        result = _unavailable("lookup_failed", "외부 평판 정보를 확인하지 못했습니다.")
    result["status_code"] = status_code
    return result


def get_url_report(url: str) -> dict[str, Any]:
    failure = _configuration_failure()
    if failure:
        return failure
    url_id = make_url_id(url)
    response, failure = _request(requests.get, f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}")
    if failure:
        return failure
    if response.status_code == 404:
        if VIRUSTOTAL_SUBMIT_IF_NOT_FOUND:
            return submit_url_for_analysis(url)
        return _unavailable("report_missing", "이 주소의 외부 평판 리포트가 없습니다.")
    if response.status_code != 200:
        return _http_failure(response.status_code)
    try:
        data = response.json()["data"]
        attributes = data["attributes"]
        stats = attributes["last_analysis_stats"]
        # Missing detection data is not a zero-detection report.
        normalized = {
            "malicious": int(stats["malicious"]),
            "suspicious": int(stats["suspicious"]),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "timeout": int(stats.get("timeout", 0)),
        }
        if any(value < 0 for value in normalized.values()):
            raise ValueError("Invalid report counts")
        return {
            "enabled": True, "available": True, "lookup_status": "available",
            "source": "url_report", "url_id": data.get("id", url_id),
            "stats": normalized,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories") or {}, "error": None,
        }
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return _unavailable("lookup_failed", "외부 평판 리포트를 확인하지 못했습니다.")


def submit_url_for_analysis(url: str) -> dict[str, Any]:
    """Submit only under the existing enabled + 404 policy; never poll."""
    failure = _configuration_failure()
    if failure:
        return failure
    response, failure = _request(requests.post, f"{VIRUSTOTAL_BASE_URL}/urls", data={"url": url})
    if failure:
        return failure
    if response.status_code != 200:
        return _http_failure(response.status_code)
    try:
        analysis_id = response.json()["data"]["id"]
        if not isinstance(analysis_id, str) or not analysis_id:
            raise ValueError("Invalid analysis identifier")
    except (ValueError, TypeError, KeyError, AttributeError):
        return _unavailable("lookup_failed", "외부 평판 분석 요청을 확인하지 못했습니다.")
    # Acceptance is not a completed report and never implies zero detections.
    result = _unavailable("submitted", "외부 평판 분석이 요청되었지만 리포트는 아직 확인되지 않았습니다.")
    result.update(source="submitted_analysis", analysis_id=analysis_id)
    return result
