"""Adapter from the production structure-preserving parser to research output."""

from app.services.qr_analyzer import (
    ACTION_SCHEMES,
    _parse_email_payload,
    _parse_sms_payload,
    analyze_non_url_qr,
    decode_repeatedly,
)

from research.parsing_types import ParserResult


def parse_proposed(raw_qr: str) -> ParserResult:
    """Expose the actual production parser through the common result schema."""
    try:
        original = raw_qr.strip()
        analysis = analyze_non_url_qr(original)
        qr_type = analysis["qr_type"]
        has_action_scheme = any(
            original.casefold().startswith(scheme)
            for scheme in ACTION_SCHEMES
        )
        parse_source = (
            original
            if has_action_scheme
            else decode_repeatedly(original, max_rounds=3)
        )

        body: str | None = None
        subject: str | None = None
        recipient: str | None = None
        if qr_type == "sms":
            parsed = _parse_sms_payload(parse_source)
            if parsed is not None:
                recipient, body = parsed
        elif qr_type == "email":
            parsed = _parse_email_payload(parse_source)
            if parsed is not None:
                recipient, subject, body = parsed

        if qr_type in {"sms", "email"}:
            urls = analysis.get("_embedded_body_urls") or []
        else:
            urls = analysis.get("extracted_urls") or []

        return ParserResult(
            qr_type=qr_type,
            body=body,
            subject=subject,
            recipient=recipient,
            extracted_urls=tuple(urls),
            extracted_url_candidates=tuple(
                analysis.get("extracted_url_candidates") or []
            ),
        )
    except Exception:
        return ParserResult(qr_type=None, parse_success=False)

