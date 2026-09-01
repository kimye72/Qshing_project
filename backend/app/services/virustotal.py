import base64
import os
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() == "true"
VIRUSTOTAL_SUBMIT_IF_NOT_FOUND = os.getenv("VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", "false").lower() == "true"
VIRUSTOTAL_TIMEOUT_SECONDS = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


def make_url_id(url: str) -> str:
    """
    VirusTotal URL report 조회에 사용할 URL identifier를 생성합니다.

    VirusTotal v3는 URL identifier로 URL을 base64 URL-safe 방식으로 인코딩하고
    끝의 '=' padding을 제거한 값을 사용할 수 있습니다.
    """
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def _headers() -> Dict[str, str]:
    return {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }


def _disabled_result() -> Dict[str, Any]:
    return {
        "enabled": False,
        "available": False,
        "error": "VirusTotal 연동이 비활성화되어 있습니다. .env에서 VIRUSTOTAL_ENABLED=true와 VIRUSTOTAL_API_KEY를 설정하세요.",
    }


def _missing_key_result() -> Dict[str, Any]:
    return {
        "enabled": True,
        "available": False,
        "error": "VIRUSTOTAL_API_KEY가 설정되어 있지 않습니다.",
    }


def get_url_report(url: str) -> Dict[str, Any]:
    """VirusTotal에 이미 존재하는 URL 리포트를 조회합니다."""
    if not VIRUSTOTAL_ENABLED:
        return _disabled_result()

    if not VIRUSTOTAL_API_KEY:
        return _missing_key_result()

    url_id = make_url_id(url)
    endpoint = f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers=_headers(),
            timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {
            "enabled": True,
            "available": False,
            "url_id": url_id,
            "error": f"VirusTotal 요청 실패: {exc}",
        }

    if response.status_code == 200:
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        categories = attributes.get("categories", {}) or {}

        return {
            "enabled": True,
            "available": True,
            "source": "url_report",
            "url_id": data.get("id", url_id),
            "stats": {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "timeout": int(stats.get("timeout", 0)),
            },
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": categories,
            "error": None,
        }

    if response.status_code == 404:
        if VIRUSTOTAL_SUBMIT_IF_NOT_FOUND:
            return submit_url_for_analysis(url)
        return {
            "enabled": True,
            "available": False,
            "url_id": url_id,
            "error": "VirusTotal에 기존 URL 리포트가 없습니다. 필요하면 VIRUSTOTAL_SUBMIT_IF_NOT_FOUND=true로 제출 기능을 켤 수 있습니다.",
        }

    try:
        error_body: Optional[Dict[str, Any]] = response.json()
    except ValueError:
        error_body = None

    return {
        "enabled": True,
        "available": False,
        "url_id": url_id,
        "status_code": response.status_code,
        "error": f"VirusTotal 응답 오류: HTTP {response.status_code}",
        "error_body": error_body,
    }


def submit_url_for_analysis(url: str) -> Dict[str, Any]:
    """
    VirusTotal에 URL 분석을 제출합니다.

    주의: URL 제출은 외부 서비스로 URL을 전송하는 동작입니다.
    민감한 토큰이나 개인정보가 포함된 URL은 제출하지 않는 것이 좋습니다.
    """
    if not VIRUSTOTAL_ENABLED:
        return _disabled_result()

    if not VIRUSTOTAL_API_KEY:
        return _missing_key_result()

    try:
        response = requests.post(
            f"{VIRUSTOTAL_BASE_URL}/urls",
            headers={**_headers(), "content-type": "application/x-www-form-urlencoded"},
            data={"url": url},
            timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {
            "enabled": True,
            "available": False,
            "error": f"VirusTotal 제출 실패: {exc}",
        }

    if response.status_code == 200:
        data = response.json().get("data", {})
        return {
            "enabled": True,
            "available": True,
            "source": "submitted_analysis",
            "analysis_id": data.get("id"),
            "stats": None,
            "error": "URL을 VirusTotal에 제출했습니다. 분석 결과는 잠시 후 URL 리포트 조회에서 확인될 수 있습니다.",
        }

    try:
        error_body: Optional[Dict[str, Any]] = response.json()
    except ValueError:
        error_body = None

    return {
        "enabled": True,
        "available": False,
        "status_code": response.status_code,
        "error": f"VirusTotal 제출 응답 오류: HTTP {response.status_code}",
        "error_body": error_body,
    }
