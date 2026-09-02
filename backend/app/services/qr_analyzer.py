import re
from urllib.parse import parse_qs, unquote, urlparse

from app.constants import (
    DANGEROUS_SCHEME_SCORE,
    MAX_URL_CANDIDATES,
    NON_URL_SCORING_VERSION,
    SCORE_IMPERSONATION_WITH_SENSITIVE_REQUEST,
    SCORE_LONG_CONTENT_WITH_MULTI_SOCIAL,
    SCORE_MULTI_SOCIAL_WITH_EXPLICIT_URL,
    SCORE_PRIZE_WITH_PERSONAL_INFO,
    SCORE_URGENCY_WITH_CREDENTIAL_OR_PERSONAL_INFO,
    SCORE_URGENCY_WITH_PAYMENT,
    SOCIAL_ENGINEERING_CATEGORY_SCORES,
    STRUCTURED_TEXT_PREVIEW_MAX_LENGTH,
    WIFI_SSID_PREVIEW_MAX_LENGTH,
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE
)

DOMAIN_LABEL_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
URL_CANDIDATE_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9@._-])"
    rf"(?P<candidate>"
    rf"(?P<domain>(?:{DOMAIN_LABEL_PATTERN}\.)+"
    rf"(?:[A-Za-z]{{2,63}}|xn--[A-Za-z0-9-]{{2,59}}))"
    rf"(?P<suffix>[/?#][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?"
    rf")"
    rf"(?![A-Za-z0-9-])",
    re.IGNORECASE,
)

DOMAIN_LABEL_VALIDATOR = re.compile(rf"^{DOMAIN_LABEL_PATTERN}$", re.IGNORECASE)
PUNYCODE_TLD_PATTERN = re.compile(r"^xn--[A-Za-z0-9-]{2,59}$", re.IGNORECASE)

COMMON_FILE_EXTENSIONS = {
    "csv",
    "dll",
    "doc",
    "docx",
    "exe",
    "gif",
    "jpeg",
    "jpg",
    "json",
    "pdf",
    "png",
    "ppt",
    "pptx",
    "svg",
    "txt",
    "xls",
    "xlsx",
    "xml",
    "zip",
}

PHONE_PATTERN = re.compile(
    r"01[016789][-\s]?\d{3,4}[-\s]?\d{4}"
)

EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

SENSITIVE_KEYWORDS = [
    "인증번호",
    "비밀번호",
    "계좌",
    "송금",
    "입금",
    "환불",
    "카드번호",
    "보안코드",
    "otp",
    "로그인",
    "고객센터",
    "긴급",
    "당첨",
    "본인확인",
    "개인정보",
]

DANGEROUS_SCHEMES = [
    "javascript:",
    "data:",
    "file:",
]

ACTION_SCHEMES = {
    "tel:": "phone",
    "sms:": "sms",
    "smsto:": "sms",
    "mailto:": "email",
    "wifi:": "wifi",
}

SOCIAL_ENGINEERING_KEYWORDS = {
    "credential_request": (
        "인증번호",
        "otp",
        "비밀번호",
        "로그인",
        "보안코드",
        "계정확인",
    ),
    "payment_request": (
        "송금",
        "입금",
        "계좌",
        "결제",
        "환불",
        "카드번호",
    ),
    "urgency": (
        "긴급",
        "즉시",
        "지금",
        "제한",
        "정지",
    ),
    "impersonation_support": (
        "고객센터",
        "상담원",
        "관리자",
        "보안팀",
    ),
    "prize_reward": (
        "당첨",
        "이벤트",
        "무료",
        "쿠폰",
    ),
    "personal_info_request": (
        "개인정보",
        "주민번호",
        "생년월일",
        "본인확인",
        "본인인증",
    ),
}

SOCIAL_ENGINEERING_CATEGORY_LABELS = {
    "credential_request": "인증정보 또는 로그인 요구",
    "payment_request": "결제 또는 송금 요구",
    "urgency": "긴급성 또는 이용 제한 강조",
    "impersonation_support": "기관·관리자·고객지원 사칭 가능 표현",
    "prize_reward": "당첨 또는 보상 제공 표현",
    "personal_info_request": "개인정보 또는 본인확인 요구",
}

COMBINED_SIGNAL_REASONS = {
    "URGENCY_WITH_CREDENTIAL_OR_PERSONAL_INFO": (
        "긴급성 표현과 인증 또는 개인정보 요구가 함께 포함되어 있습니다."
    ),
    "URGENCY_WITH_PAYMENT": "긴급성 표현과 결제 또는 송금 요구가 함께 포함되어 있습니다.",
    "IMPERSONATION_WITH_SENSITIVE_REQUEST": (
        "기관·관리자 사칭 가능 표현과 민감한 행동 요구가 함께 포함되어 있습니다."
    ),
    "PRIZE_WITH_PERSONAL_INFO": "보상 제공 표현과 개인정보 요구가 함께 포함되어 있습니다.",
    "MULTI_SOCIAL_WITH_EXPLICIT_URL": (
        "여러 사회공학 신호와 명시적인 URL이 함께 포함되어 있습니다."
    ),
    "LONG_CONTENT_WITH_MULTI_SOCIAL": (
        "긴 콘텐츠 안에 여러 사회공학 신호가 함께 포함되어 있습니다."
    ),
}


def decode_repeatedly(value: str, max_rounds: int = 3) -> str:
    """
    URL 인코딩된 문자열을 여러 번 디코딩한다.
    예: %253Cscript%253E → %3Cscript%3E → <script>
    """
    decoded = value

    for _ in range(max_rounds):
        next_decoded = unquote(decoded)

        if next_decoded == decoded:
            break

        decoded = next_decoded

    return decoded


def _mask_phone_number(value: str) -> str | None:
    compact = re.sub(r"[^0-9+]", "", value.strip())
    has_country_prefix = compact.startswith("+")
    digits = compact[1:] if has_country_prefix else compact
    if not digits.isdigit() or len(digits) < 7:
        return None

    prefix_length = 4 if has_country_prefix else 3
    prefix = digits[:prefix_length]
    return f"{'+' if has_country_prefix else ''}{prefix}****{digits[-4:]}"


def _mask_email_address(value: str) -> str | None:
    local_part, separator, domain = value.strip().rpartition("@")
    if not separator or not local_part or not domain:
        return None
    return f"{local_part[0]}***@{domain.lower()}"


def mask_sensitive_content(content: str) -> str:
    """
    화면이나 DB에 저장할 때 민감할 수 있는 정보를 일부 마스킹한다.
    """
    masked = content

    # 휴대전화 번호 마스킹
    masked = re.sub(
        r"(01[016789])[-\s]?(\d{3,4})[-\s]?(\d{4})",
        r"\1-****-\3",
        masked,
    )

    masked = re.sub(
        r"\+82[-\s]?10[-\s]?\d{3,4}[-\s]?\d{4}",
        lambda match: _mask_phone_number(match.group(0)) or "****",
        masked,
    )

    # 이메일 일부 마스킹
    masked = EMAIL_PATTERN.sub(
        lambda match: _mask_email_address(match.group(0)) or "***",
        masked,
    )

    # 너무 긴 QR 내용은 일부만 표시
    if len(masked) > 200:
        masked = masked[:200] + "..."

    return masked


def _limited_sensitive_preview(value: str, max_length: int) -> str:
    masked = mask_sensitive_content(value)
    if len(masked) <= max_length:
        return masked
    if max_length <= 3:
        return masked[:max_length]
    return masked[:max_length - 3] + "..."


def _split_unescaped(
    value: str,
    separator: str,
    *,
    maxsplit: int = -1,
) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    splits = 0

    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == separator and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(current))
            current = []
            splits += 1
            continue
        current.append(character)

    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def _unescape_qr_value(value: str) -> str:
    unescaped: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            unescaped.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            unescaped.append(character)
    if escaped:
        unescaped.append("\\")
    return "".join(unescaped)


def _parse_wifi_fields(content: str) -> dict[str, str]:
    if not content.lower().startswith("wifi:"):
        return {}

    fields: dict[str, str] = {}
    for field in _split_unescaped(content[5:], ";"):
        key_value = _split_unescaped(field, ":", maxsplit=1)
        if len(key_value) != 2:
            continue
        key = _unescape_qr_value(key_value[0]).upper()
        if key in {"T", "S", "P", "H"}:
            fields[key] = decode_repeatedly(_unescape_qr_value(key_value[1]))
    return fields


def _redact_wifi_password(content: str) -> str:
    if not content.lower().startswith("wifi:"):
        return content

    redacted_fields: list[str] = []
    for field in _split_unescaped(content[5:], ";"):
        key_value = _split_unescaped(field, ":", maxsplit=1)
        if len(key_value) == 2 and _unescape_qr_value(key_value[0]).upper() == "P":
            redacted_fields.append(f"{key_value[0]}:****")
        else:
            redacted_fields.append(field)
    return content[:5] + ";".join(redacted_fields)


def _first_query_value(query: str, key: str) -> str | None:
    values = parse_qs(query, keep_blank_values=True).get(key)
    if not values:
        return None
    # parse_qs already performs one decoding pass. Decode at most two more
    # times after the query boundary has been established.
    return decode_repeatedly(values[0], max_rounds=2)


def _parse_phone_content(content: str, qr_type: str) -> dict | None:
    if qr_type == "phone":
        number = content.split(":", 1)[1] if ":" in content else ""
    else:
        match = PHONE_PATTERN.search(content)
        number = match.group(0) if match else ""

    number = decode_repeatedly(number)
    masked = _mask_phone_number(number)
    return {"phone_number_masked": masked} if masked else None


def _parse_sms_payload(content: str) -> tuple[str, str | None] | None:
    lower = content.lower()

    if lower.startswith("smsto:"):
        payload = content[6:]
        recipient, separator, body_value = payload.partition(":")
        body = decode_repeatedly(body_value) if separator else None
    elif lower.startswith("sms:"):
        payload = content[4:]
        recipient, separator, query = payload.partition("?")
        body = _first_query_value(query, "body") if separator else None
    else:
        return None

    return decode_repeatedly(recipient), body


def _parse_sms_content(content: str) -> dict | None:
    parsed = _parse_sms_payload(content)
    if parsed is None:
        return None
    recipient, body = parsed

    metadata: dict = {}
    masked_recipient = _mask_phone_number(recipient.split(",", 1)[0])
    if masked_recipient:
        metadata["sms_recipient_masked"] = masked_recipient
    if body is not None:
        metadata["sms_body_preview"] = _limited_sensitive_preview(
            body,
            STRUCTURED_TEXT_PREVIEW_MAX_LENGTH,
        )
        metadata["sms_body_length"] = len(body)
    return metadata or None


def _parse_email_payload(content: str) -> tuple[str, str | None, str | None] | None:
    if not content.lower().startswith("mailto:"):
        return None

    payload = content.split(":", 1)[1] if ":" in content else ""
    address, separator, query = payload.partition("?")
    return (
        decode_repeatedly(address.split(",", 1)[0].strip()),
        _first_query_value(query, "subject") if separator else None,
        _first_query_value(query, "body") if separator else None,
    )


def _parse_email_content(content: str, qr_type: str) -> dict | None:
    parsed = _parse_email_payload(content) if qr_type == "email" else None
    if parsed is not None:
        address, subject, body = parsed
    else:
        match = EMAIL_PATTERN.search(content)
        address = match.group(0) if match else ""
        subject = None
        body = None

    metadata: dict = {}
    if EMAIL_PATTERN.fullmatch(address):
        masked_address = _mask_email_address(address)
        if masked_address:
            metadata["email_address_masked"] = masked_address
        metadata["email_domain"] = address.rsplit("@", 1)[1].lower()
    if subject is not None:
        metadata["email_subject_preview"] = _limited_sensitive_preview(
            subject,
            STRUCTURED_TEXT_PREVIEW_MAX_LENGTH,
        )
    if body is not None:
        metadata["email_body_preview"] = _limited_sensitive_preview(
            body,
            STRUCTURED_TEXT_PREVIEW_MAX_LENGTH,
        )
        metadata["email_body_length"] = len(body)
    return metadata or None


def _parse_wifi_content(content: str) -> dict | None:
    fields = _parse_wifi_fields(content)
    if not fields:
        return None

    security_type = fields.get("T")
    password = fields.get("P", "")
    metadata: dict = {
        "wifi_hidden": fields.get("H", "").lower() in {"true", "1", "yes"},
        "wifi_has_password": bool(password)
        and (security_type or "").lower() != "nopass",
    }
    if security_type:
        metadata["wifi_security_type"] = security_type[:20]
    if "S" in fields:
        metadata["wifi_ssid_preview"] = _limited_sensitive_preview(
            fields["S"],
            WIFI_SSID_PREVIEW_MAX_LENGTH,
        )
    return metadata


def _parse_structured_content(content: str, qr_type: str) -> dict | None:
    try:
        if qr_type in {"phone", "phone_text"}:
            return _parse_phone_content(content, qr_type)
        if qr_type == "sms":
            return _parse_sms_content(content)
        if qr_type in {"email", "email_text"}:
            return _parse_email_content(content, qr_type)
        if qr_type == "wifi":
            return _parse_wifi_content(content)
    except Exception:
        return None
    return None


def _detect_social_engineering_categories(content: str) -> list[str]:
    lower = content.lower()
    return [
        category
        for category, keywords in SOCIAL_ENGINEERING_KEYWORDS.items()
        if any(keyword.lower() in lower for keyword in keywords)
    ]


def _score_social_engineering(
    categories: list[str],
    *,
    has_explicit_url: bool,
    long_content: bool,
) -> tuple[int, int, int, list[str]]:
    category_set = set(categories)
    category_score = sum(
        SOCIAL_ENGINEERING_CATEGORY_SCORES.get(category, 0)
        for category in category_set
    )
    combined_score = 0
    long_content_score = 0
    triggered_rules: list[str] = []
    sensitive_requests = {
        "credential_request",
        "payment_request",
        "personal_info_request",
    }

    if "urgency" in category_set and category_set.intersection(
        {"credential_request", "personal_info_request"}
    ):
        combined_score += SCORE_URGENCY_WITH_CREDENTIAL_OR_PERSONAL_INFO
        triggered_rules.append("URGENCY_WITH_CREDENTIAL_OR_PERSONAL_INFO")

    if {"urgency", "payment_request"}.issubset(category_set):
        combined_score += SCORE_URGENCY_WITH_PAYMENT
        triggered_rules.append("URGENCY_WITH_PAYMENT")

    if "impersonation_support" in category_set and category_set.intersection(
        sensitive_requests
    ):
        combined_score += SCORE_IMPERSONATION_WITH_SENSITIVE_REQUEST
        triggered_rules.append("IMPERSONATION_WITH_SENSITIVE_REQUEST")

    if {"prize_reward", "personal_info_request"}.issubset(category_set):
        combined_score += SCORE_PRIZE_WITH_PERSONAL_INFO
        triggered_rules.append("PRIZE_WITH_PERSONAL_INFO")

    if (
        has_explicit_url
        and len(category_set) >= 2
        and category_set.intersection(sensitive_requests)
    ):
        combined_score += SCORE_MULTI_SOCIAL_WITH_EXPLICIT_URL
        triggered_rules.append("MULTI_SOCIAL_WITH_EXPLICIT_URL")

    if long_content and len(category_set) >= 2:
        long_content_score = SCORE_LONG_CONTENT_WITH_MULTI_SOCIAL
        triggered_rules.append("LONG_CONTENT_WITH_MULTI_SOCIAL")

    return (
        category_score,
        combined_score,
        long_content_score,
        triggered_rules,
    )


def extract_urls(content: str) -> list[str]:
    """
    일반 텍스트 안에 포함된 URL을 추출한다.
    """
    return URL_PATTERN.findall(content)


def _extract_structured_body_urls(content: str, qr_type: str) -> list[str]:
    """Extract explicit HTTP(S) URLs only from an SMS or mail body."""
    try:
        if qr_type == "sms":
            parsed_sms = _parse_sms_payload(content)
            body = parsed_sms[1] if parsed_sms is not None else None
        elif qr_type == "email":
            parsed_email = _parse_email_payload(content)
            body = parsed_email[2] if parsed_email is not None else None
        else:
            return []
        return extract_urls(body) if body else []
    except Exception:
        return []


def _spans_overlap(first: tuple[int, int], second: tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def _is_valid_domain_candidate(domain: str, *, has_suffix: bool) -> bool:
    if len(domain) > 253:
        return False

    labels = domain.split(".")
    if len(labels) < 2 or any(
        not DOMAIN_LABEL_VALIDATOR.fullmatch(label) for label in labels
    ):
        return False

    tld = labels[-1]
    if not (tld.isalpha() or PUNYCODE_TLD_PATTERN.fullmatch(tld)):
        return False

    if not has_suffix and tld.lower() in COMMON_FILE_EXTENSIONS:
        return False

    return True


def extract_url_candidates(content: str) -> list[str]:
    """Extract validated schemeless domain candidates without inferring a scheme."""
    excluded_spans = [match.span() for match in URL_PATTERN.finditer(content)]
    excluded_spans.extend(match.span() for match in EMAIL_PATTERN.finditer(content))

    candidates: list[str] = []
    seen: set[str] = set()

    for match in URL_CANDIDATE_PATTERN.finditer(content):
        if any(_spans_overlap(match.span(), span) for span in excluded_spans):
            continue

        candidate = match.group("candidate").rstrip(".,;:!?)]}")
        if not candidate:
            continue

        domain = match.group("domain")
        has_suffix = len(candidate) > len(domain)
        if not _is_valid_domain_candidate(domain, has_suffix=has_suffix):
            continue

        dedupe_key = candidate.casefold()
        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)
        candidates.append(candidate)

    return candidates


def detect_qr_type(
    content: str,
    *,
    extracted_urls: list[str] | None = None,
    extracted_url_candidates: list[str] | None = None,
) -> str:
    """
    QR 내용의 유형을 분류한다.
    """
    text = content.strip()
    lower = text.lower()

    if (
        lower.startswith("http://") or lower.startswith("https://")
    ) and URL_PATTERN.fullmatch(text):
        return "url"

    for scheme, qr_type in ACTION_SCHEMES.items():
        if lower.startswith(scheme):
            return qr_type

    for scheme in DANGEROUS_SCHEMES:
        if lower.startswith(scheme):
            return "dangerous_scheme"

    urls = extract_urls(text) if extracted_urls is None else extracted_urls
    candidates = (
        extract_url_candidates(text)
        if extracted_url_candidates is None
        else extracted_url_candidates
    )

    if urls or candidates:
        return "text_with_url"

    if PHONE_PATTERN.search(text):
        return "phone_text"

    if EMAIL_PATTERN.search(text):
        return "email_text"

    return "text"


def analyze_non_url_qr(content: str) -> dict:
    """
    URL이 아닌 QR 또는 일반 QR 내용을 분석한다.
    URL 자체 분석은 기존 scanner.py의 analyze_url()이 담당하고,
    이 함수는 비URL QR의 위험도를 판단하는 역할을 한다.
    """
    original_content = content.strip()
    decoded_content = decode_repeatedly(original_content)
    lower_decoded = decoded_content.lower()
    has_explicit_action_scheme = any(
        original_content.lower().startswith(scheme)
        for scheme in ACTION_SCHEMES
    )
    structured_parse_content = (
        original_content if has_explicit_action_scheme else decoded_content
    )
    public_analysis_content = (
        _redact_wifi_password(decoded_content)
        if lower_decoded.startswith("wifi:")
        else decoded_content
    )

    extracted_urls = extract_urls(public_analysis_content)
    all_url_candidates = extract_url_candidates(public_analysis_content)
    extracted_url_candidates = all_url_candidates[:MAX_URL_CANDIDATES]
    qr_type = detect_qr_type(
        decoded_content,
        extracted_urls=extracted_urls,
        extracted_url_candidates=all_url_candidates,
    )
    structured_content = _parse_structured_content(structured_parse_content, qr_type)
    embedded_body_urls = _extract_structured_body_urls(
        structured_parse_content,
        qr_type,
    )
    social_engineering_categories = _detect_social_engineering_categories(
        public_analysis_content
    )
    has_explicit_url_context = bool(
        embedded_body_urls
        if qr_type in {"sms", "email"}
        else extracted_urls
    )
    long_content = len(decoded_content) >= 300
    (
        social_engineering_score,
        combined_signal_score,
        long_content_score,
        combined_signal_rules,
    ) = _score_social_engineering(
        social_engineering_categories,
        has_explicit_url=has_explicit_url_context,
        long_content=long_content,
    )

    risk_score = 0
    reasons: list[str] = []

    analysis_flags = {
        "decoded_changed": decoded_content != original_content,
        "contains_url": len(extracted_urls) > 0,
        "contains_url_candidate": len(all_url_candidates) > 0,
        "url_candidate_count": len(all_url_candidates),
        "contains_phone": bool(PHONE_PATTERN.search(decoded_content)),
        "contains_email": bool(EMAIL_PATTERN.search(decoded_content)),
        "sensitive_keyword_count": 0,
        "dangerous_scheme": False,
        "long_content": long_content,
        "has_structured_phone": bool(
            structured_content and qr_type in {"phone", "phone_text"}
        ),
        "has_structured_sms": bool(structured_content and qr_type == "sms"),
        "has_structured_email": bool(
            structured_content and qr_type in {"email", "email_text"}
        ),
        "has_structured_wifi": bool(structured_content and qr_type == "wifi"),
        "social_engineering_category_count": len(
            social_engineering_categories
        ),
        "non_url_scoring_version": NON_URL_SCORING_VERSION,
        "score_components": {
            "dangerous_scheme": 0,
            "social_engineering": social_engineering_score,
            "combined_signals": combined_signal_score,
            "long_content": long_content_score,
        },
        "combined_signal_rules": combined_signal_rules,
    }

    if decoded_content != original_content:
        reasons.append("인코딩된 QR 내용이 포함되어 있어 디코딩 후 추가 검사를 수행했습니다.")

    for scheme in DANGEROUS_SCHEMES:
        if lower_decoded.startswith(scheme):
            risk_score += DANGEROUS_SCHEME_SCORE
            analysis_flags["dangerous_scheme"] = True
            analysis_flags["score_components"][
                "dangerous_scheme"
            ] = DANGEROUS_SCHEME_SCORE
            reasons.append(f"위험한 실행형 스킴이 포함되어 있습니다: {scheme}")

    if qr_type == "phone" or qr_type == "phone_text":
        reasons.append("전화번호 형식의 QR 콘텐츠입니다.")

    if qr_type == "sms":
        reasons.append("문자 작성 정보가 포함된 QR입니다.")

    if qr_type == "email" or qr_type == "email_text":
        reasons.append("이메일 작성 정보가 포함된 QR입니다.")

    if qr_type == "wifi":
        reasons.append("Wi-Fi 연결 정보가 포함된 QR입니다.")

    if extracted_urls or all_url_candidates:
        if extracted_urls:
            reasons.append("일반 텍스트 안에 URL이 포함되어 있습니다. 포함된 URL 분석이 필요합니다.")

    if all_url_candidates:
        reasons.append("프로토콜이 명시되지 않은 URL 형태의 문자열이 포함되어 있습니다.")

    analysis_flags["sensitive_keyword_count"] = sum(
        keyword.lower() in lower_decoded for keyword in SENSITIVE_KEYWORDS
    )

    for category in social_engineering_categories:
        reasons.append(
            "사회공학 위험 신호가 포함되어 있습니다: "
            f"{SOCIAL_ENGINEERING_CATEGORY_LABELS[category]}."
        )

    for rule_id in combined_signal_rules:
        reasons.append(COMBINED_SIGNAL_REASONS[rule_id])

    risk_score += (
        social_engineering_score
        + combined_signal_score
        + long_content_score
    )

    if PHONE_PATTERN.search(decoded_content):
        reasons.append("휴대전화 번호 형식이 포함되어 있습니다.")

    if EMAIL_PATTERN.search(decoded_content):
        reasons.append("이메일 주소 형식이 포함되어 있습니다.")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        status = "danger"
        message = "위험 가능성이 높은 QR입니다. 자동 실행하거나 안내된 행동을 바로 수행하지 마세요."
    elif risk_score >= 30:
        status = "warning"
        message = "주의가 필요한 QR입니다. 포함된 연락처, 계좌, 인증번호 요청 등을 반드시 확인하세요."
    else:
        status = "safe"
        message = "URL이 아닌 QR입니다. 현재 기준으로는 높은 위험 요소가 발견되지 않았습니다."

    if not reasons:
        reasons.append("URL이 아닌 일반 텍스트 QR로 분류되었습니다.")

    first_url = extracted_urls[0] if extracted_urls else None
    try:
        domain = urlparse(first_url).netloc if first_url else None
    except (ValueError, UnicodeError):
        domain = None

    return {
        "qr_type": qr_type,
        "raw_content_preview": mask_sensitive_content(public_analysis_content),
        "contains_url": len(extracted_urls) > 0,
        "extracted_urls": extracted_urls,
        "contains_url_candidate": len(all_url_candidates) > 0,
        "extracted_url_candidates": extracted_url_candidates,
        "candidate_url_count": len(all_url_candidates),
        "structured_content": structured_content,
        "_embedded_body_urls": embedded_body_urls,
        "social_engineering_categories": social_engineering_categories,
        "social_engineering_category_count": len(
            social_engineering_categories
        ),
        "url": first_url,
        "domain": domain,
        "risk_score": risk_score,
        "status": status,
        "message": message,
        "reasons": reasons,
        "analysis_flags": analysis_flags,
        "raw_result": {
            "original_length": len(original_content),
            "decoded_length": len(decoded_content),
            "decoded_changed": decoded_content != original_content,
            "qr_type": qr_type,
            "candidate_url_count": len(all_url_candidates),
        },
    }
