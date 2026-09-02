"""Decode-first parser used only as the research comparison baseline."""

from urllib.parse import parse_qs, urlsplit

from app.services.qr_analyzer import (
    decode_repeatedly,
    detect_qr_type,
    extract_url_candidates,
    extract_urls,
)

from research.parsing_types import ParserResult


def _first_value(query: str, key: str) -> str | None:
    values = parse_qs(query, keep_blank_values=True).get(key)
    return values[0] if values else None


def parse_baseline(raw_qr: str) -> ParserResult:
    """Parse after decoding the complete QR string up to three times.

    This models a reasonable naive implementation: normalize encoded input
    first, then apply the standard URI and query-string parsers. It is kept
    outside the production path and deliberately has no case-specific logic.
    """
    try:
        decoded = decode_repeatedly(raw_qr.strip(), max_rounds=3)
        qr_type = detect_qr_type(decoded)
        body: str | None = None
        subject: str | None = None
        recipient: str | None = None

        if qr_type == "sms":
            split = urlsplit(decoded)
            if split.scheme.casefold() == "smsto":
                recipient, separator, body_value = split.path.partition(":")
                body = body_value if separator else None
            else:
                recipient = split.path
                body = _first_value(split.query, "body")
        elif qr_type == "email":
            split = urlsplit(decoded)
            recipient = split.path.split(",", 1)[0].strip()
            subject = _first_value(split.query, "subject")
            body = _first_value(split.query, "body")

        url_source = body if qr_type in {"sms", "email"} else decoded
        urls = extract_urls(url_source or "")
        candidates = extract_url_candidates(url_source or "")
        return ParserResult(
            qr_type=qr_type,
            body=body,
            subject=subject,
            recipient=recipient,
            extracted_urls=tuple(urls),
            extracted_url_candidates=tuple(candidates),
        )
    except Exception:
        return ParserResult(qr_type=None, parse_success=False)

