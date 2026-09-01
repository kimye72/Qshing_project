import ipaddress
import re
from urllib.parse import unquote, urlparse

from app.constants import RULESET_VERSION
from app.services.virustotal import get_url_report


DANGEROUS_SCHEMES = {"javascript", "data", "file", "ftp"}
ALLOWED_SCHEMES = {"http", "https"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "password",
    "wallet",
    "gift",
    "free",
    "event",
    "coupon",
]
SQL_XSS_PATTERNS = [
    (r"\bselect\b", "SQL 의심 키워드 포함: select"),
    (r"\bunion\b", "SQL 의심 키워드 포함: union"),
    (r"\binsert\b", "SQL 의심 키워드 포함: insert"),
    (r"\bdelete\b", "SQL 의심 키워드 포함: delete"),
    (r"\bdrop\b", "SQL 의심 키워드 포함: drop"),
    (r"\bor\s+1\s*=\s*1\b", "SQL Injection 의심 패턴 포함"),
    (r"<\s*script\b", "XSS 의심 패턴 포함: script 태그"),
    (r"onerror\s*=", "XSS 의심 패턴 포함: onerror 이벤트"),
    (r"onload\s*=", "XSS 의심 패턴 포함: onload 이벤트"),
]
BRAND_KEYWORDS = ["naver", "kakao", "google", "apple", "paypal", "bank", "pay"]
BRAND_SAFE_DOMAINS = {
    "naver": ["naver.com", "www.naver.com"],
    "kakao": ["kakao.com", "www.kakao.com", "kakaocorp.com"],
    "google": ["google.com", "www.google.com"],
    "apple": ["apple.com", "www.apple.com"],
    "paypal": ["paypal.com", "www.paypal.com"],
}


def _decode_repeatedly(value: str, max_rounds: int = 3) -> tuple[str, bool]:
    """URL 인코딩을 제한된 횟수만큼 해제합니다."""
    decoded = value
    changed = False

    for _ in range(max_rounds):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
        changed = True

    return decoded, changed


def _is_ip_address(hostname: str) -> tuple[bool, bool]:
    """IP 주소 여부와 사설/내부 IP 여부를 반환합니다."""
    if not hostname:
        return False, False

    cleaned = hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False, False

    is_private_or_local = any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
        ]
    )
    return True, is_private_or_local


def _looks_like_private_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower().strip(".")
    return hostname in {"localhost", "local"} or hostname.endswith(".local")


def _is_shortener_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")
    return domain in SHORTENER_DOMAINS or any(domain.endswith(f".{item}") for item in SHORTENER_DOMAINS)


def _has_suspicious_brand_domain(domain: str) -> bool:
    """
    유명 서비스명이 도메인에 포함되어 있지만 공식 도메인이 아닌 경우를 단순 휴리스틱으로 탐지합니다.
    완벽한 피싱 탐지가 아니라 주의 신호를 추가하기 위한 보조 로직입니다.
    """
    domain = domain.lower().strip(".")
    for brand in BRAND_KEYWORDS:
        if brand not in domain:
            continue
        safe_domains = BRAND_SAFE_DOMAINS.get(brand, [])
        if domain not in safe_domains and not any(domain.endswith(f".{safe}") for safe in safe_domains):
            return True
    return False


def _get_local_heuristic_score(url: str, domain: str, decoded_url: str) -> tuple[int, list[str], dict]:
    """외부 API 없이 URL 문자열만 보고 계산하는 보조 위험 점수입니다."""
    risk_score = 10
    reasons: list[str] = []
    flags = {
        "decoded_changed": decoded_url != url,
        "non_https": False,
        "disallowed_scheme": False,
        "ip_address_host": False,
        "private_or_local_host": False,
        "long_url": False,
        "shortener": False,
        "userinfo_in_url": False,
        "suspicious_keyword_count": 0,
        "sql_xss_pattern_count": 0,
        "suspicious_brand_domain": False,
    }

    parsed = urlparse(url)
    decoded_lower = decoded_url.lower()
    original_lower = url.lower()
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or domain or "").lower().strip(".")

    if scheme in DANGEROUS_SCHEMES or scheme not in ALLOWED_SCHEMES:
        risk_score += 40
        flags["disallowed_scheme"] = True
        reasons.append(f"허용되지 않는 URL 스킴입니다: {scheme or 'unknown'}")

    if scheme == "http":
        risk_score += 20
        flags["non_https"] = True
        reasons.append("HTTPS가 아닌 HTTP 주소입니다.")

    if flags["decoded_changed"]:
        risk_score += 5
        reasons.append("URL 인코딩이 포함되어 있어 디코딩 후 추가 검사를 수행했습니다.")

    if len(url) >= 120:
        risk_score += 10
        flags["long_url"] = True
        reasons.append("URL 길이가 길어 실제 목적지를 확인하기 어렵습니다.")

    is_ip, is_private_or_local = _is_ip_address(hostname)
    if is_ip:
        risk_score += 25
        flags["ip_address_host"] = True
        reasons.append("도메인 대신 IP 주소를 직접 사용하고 있습니다.")

    if is_private_or_local or _looks_like_private_hostname(hostname):
        risk_score += 50
        flags["private_or_local_host"] = True
        reasons.append("localhost 또는 사설/내부망 주소로 보이는 호스트입니다.")

    if "@" in parsed.netloc:
        risk_score += 25
        flags["userinfo_in_url"] = True
        reasons.append("URL 사용자 정보 영역(@)을 사용하여 실제 도메인을 숨길 수 있습니다.")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in original_lower or keyword in decoded_lower:
            risk_score += 10
            flags["suspicious_keyword_count"] += 1
            reasons.append(f"의심 키워드 포함: {keyword}")

    if _is_shortener_domain(hostname):
        risk_score += 20
        flags["shortener"] = True
        reasons.append("단축 URL 서비스를 사용하고 있습니다.")

    if _has_suspicious_brand_domain(hostname):
        risk_score += 15
        flags["suspicious_brand_domain"] = True
        reasons.append("유명 서비스명을 포함하지만 공식 도메인으로 보기 어려운 주소입니다.")

    for pattern, reason in SQL_XSS_PATTERNS:
        if re.search(pattern, decoded_lower, flags=re.IGNORECASE):
            risk_score += 10
            flags["sql_xss_pattern_count"] += 1
            reasons.append(reason)

    return risk_score, reasons, flags


def _apply_virustotal_score(risk_score: int, reasons: list[str], vt_result: dict) -> int:
    """VirusTotal 탐지 통계를 위험 점수에 반영합니다."""
    if not vt_result.get("enabled"):
        return risk_score

    if not vt_result.get("available"):
        error = vt_result.get("error")
        if error:
            reasons.append(f"VirusTotal 조회 결과 미사용: {error}")
        return risk_score

    stats = vt_result.get("stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    detected = malicious + suspicious

    if malicious >= 3 or detected >= 5:
        risk_score += 70
        reasons.append(
            f"VirusTotal 탐지 결과 악성 {malicious}건, 의심 {suspicious}건이 확인되었습니다."
        )
    elif malicious >= 1 or suspicious >= 2:
        risk_score += 45
        reasons.append(
            f"VirusTotal 일부 엔진에서 악성/의심 판정이 있습니다. 악성 {malicious}건, 의심 {suspicious}건."
        )
    elif suspicious == 1:
        risk_score += 25
        reasons.append("VirusTotal 일부 엔진에서 의심 판정 1건이 확인되었습니다.")
    elif harmless > 0:
        reasons.append("VirusTotal 최근 리포트에서 악성 탐지 수가 0건입니다.")

    return risk_score


def _make_status_and_message(risk_score: int) -> tuple[str, str]:
    if risk_score >= 70:
        return "danger", "위험 가능성이 높은 URL입니다. 접속하지 않는 것을 권장합니다."
    if risk_score >= 30:
        return "warning", "주의가 필요한 URL입니다. 접속 전 주소와 출처를 다시 확인하세요."
    return "safe", "현재 기준으로는 비교적 안전한 URL입니다."


def _extract_vt_dashboard_fields(vt_result: dict) -> dict:
    stats = vt_result.get("stats") or {}
    return {
        "vt_available": bool(vt_result.get("available")),
        "vt_source": vt_result.get("source"),
        "vt_malicious": int(stats.get("malicious", 0) or 0),
        "vt_suspicious": int(stats.get("suspicious", 0) or 0),
        "vt_harmless": int(stats.get("harmless", 0) or 0),
        "vt_undetected": int(stats.get("undetected", 0) or 0),
    }


def analyze_url_with_vt_result(url: str, vt_result: dict) -> dict:
    """Apply the existing URL rules to a supplied VirusTotal result."""
    parsed = urlparse(url)
    domain = (parsed.hostname or parsed.netloc or "").lower().strip(".")
    decoded_url, _ = _decode_repeatedly(url)

    local_score, reasons, flags = _get_local_heuristic_score(url, domain, decoded_url)

    score_with_vt = _apply_virustotal_score(local_score, reasons, vt_result)
    vt_score_delta = score_with_vt - local_score
    risk_score = min(score_with_vt, 100)

    status, message = _make_status_and_message(risk_score)
    vt_dashboard_fields = _extract_vt_dashboard_fields(vt_result)

    if not reasons:
        reasons.append("특별한 위험 요소가 발견되지 않았습니다.")

    return {
        "url": url,
        "domain": domain,
        "decoded_url": decoded_url if decoded_url != url else None,
        "qr_type": "url",
        "contains_url": True,
        "extracted_urls": [url],
        "local_score": local_score,
        "vt_score_delta": vt_score_delta,
        "final_score": risk_score,
        "risk_score": risk_score,
        "ruleset_version": RULESET_VERSION,
        "status": status,
        "message": message,
        "reasons": reasons,
        "analysis_flags": flags,
        **vt_dashboard_fields,
        "raw_result": {
            "domain": domain,
            "decoded_url": decoded_url if decoded_url != url else None,
            "local_analysis": True,
            "analysis_flags": flags,
            "virustotal": vt_result,
        },
    }


def analyze_url(url: str) -> dict:
    return analyze_url_with_vt_result(url, get_url_report(url))
