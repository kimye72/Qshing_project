import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.main import _status_and_message_for_qr, resolve_direct_http_url
from app.services.qr_analyzer import (
    ACTION_SCHEMES,
    _parse_email_payload,
    _parse_sms_payload,
    analyze_non_url_qr,
    decode_repeatedly,
    detect_qr_type,
    extract_url_candidates,
    extract_urls,
)
from app.services.scanner import analyze_url_with_vt_result
from app.constants import MAX_EMBEDDED_URLS_ANALYZED
from research.evaluation.models import DetectionMode, EvaluationSample, PredictionResult


DISABLED_REPUTATION = {
    "enabled": False,
    "available": False,
    "error": None,
}


class ReputationProvider(Protocol):
    name: str

    def lookup(self, url: str) -> dict:
        ...


class DisabledReputationProvider:
    name = "disabled"

    def lookup(self, url: str) -> dict:
        del url
        return dict(DISABLED_REPUTATION)


class SnapshotReputationProvider:
    name = "snapshot"

    def __init__(self, entries: dict[str, dict]):
        self._entries = entries

    @classmethod
    def from_file(cls, path: str | Path) -> "SnapshotReputationProvider":
        with Path(path).open("r", encoding="utf-8") as snapshot_file:
            document = json.load(snapshot_file)
        entries = document.get("entries") if isinstance(document, dict) else None
        if not isinstance(entries, dict):
            raise ValueError("reputation snapshot must contain an entries object")
        if not all(isinstance(url, str) and isinstance(value, dict) for url, value in entries.items()):
            raise ValueError("reputation snapshot entries must map URL strings to objects")
        return cls(entries)

    def lookup(self, url: str) -> dict:
        result = self._entries.get(url)
        if result is None:
            return dict(DISABLED_REPUTATION)
        return {
            **result,
            "enabled": True,
            "available": bool(result.get("available", True)),
            "source": "snapshot",
        }


@dataclass(frozen=True)
class StructuredParse:
    qr_type: str
    embedded_urls: tuple[str, ...]


def _ordered_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _parse_structure(raw_qr: str) -> StructuredParse:
    """Use production parsing helpers without running social scoring."""
    original = raw_qr.strip()
    decoded = decode_repeatedly(original, max_rounds=3)
    urls = extract_urls(decoded)
    candidates = extract_url_candidates(decoded)
    qr_type = detect_qr_type(
        decoded,
        extracted_urls=urls,
        extracted_url_candidates=candidates,
    )
    has_action_scheme = any(
        original.casefold().startswith(scheme)
        for scheme in ACTION_SCHEMES
    )
    parse_source = original if has_action_scheme else decoded

    if qr_type == "sms":
        payload = _parse_sms_payload(parse_source)
        body = payload[1] if payload is not None else None
        embedded_urls = extract_urls(body) if body else []
    elif qr_type == "email":
        payload = _parse_email_payload(parse_source)
        body = payload[2] if payload is not None else None
        embedded_urls = extract_urls(body) if body else []
    else:
        embedded_urls = urls

    return StructuredParse(
        qr_type=qr_type,
        embedded_urls=_ordered_unique(embedded_urls),
    )


def _prediction_label(status: str) -> str:
    return "benign" if status == "safe" else "qshing"


def _make_prediction(
    sample: EvaluationSample,
    mode: DetectionMode,
    *,
    score: int,
    status: str,
    supported: bool,
    detected_qr_type: str | None,
    reasons: list[str] | None = None,
    extracted_urls: tuple[str, ...] = (),
    parent_score: int | None = None,
    embedded_url_max_score: int | None = None,
    social_score: int | None = None,
    local_url_score: int | None = None,
    reputation_source: str | None = None,
) -> PredictionResult:
    return PredictionResult(
        case_id=sample.case_id,
        mode=mode.value,
        ground_truth=sample.label,
        predicted_label=_prediction_label(status),
        risk_score=score,
        status=status,
        supported=supported,
        qr_type=sample.qr_type,
        detected_qr_type=detected_qr_type,
        scenario=sample.scenario,
        reasons=list(reasons or []),
        extracted_urls=list(extracted_urls),
        parent_score=parent_score,
        embedded_url_max_score=embedded_url_max_score,
        social_score=social_score,
        local_url_score=local_url_score,
        reputation_source=reputation_source,
    )


def _safe_direct_url(raw_qr: str) -> str | None:
    try:
        return resolve_direct_http_url(raw_qr.strip())
    except Exception:
        return None


def _analyze_urls(
    urls: tuple[str, ...],
    provider: ReputationProvider,
) -> list[dict]:
    results: list[dict] = []
    for url in urls[:MAX_EMBEDDED_URLS_ANALYZED]:
        try:
            results.append(analyze_url_with_vt_result(url, provider.lookup(url)))
        except (TypeError, ValueError, UnicodeError):
            continue
    return results


def _social_component_score(parent: dict) -> int:
    components = (parent.get("analysis_flags") or {}).get("score_components") or {}
    return sum(
        int(components.get(name, 0) or 0)
        for name in ("social_engineering", "combined_signals", "long_content")
    )


def analyze_sample(
    sample: EvaluationSample,
    mode: DetectionMode,
    *,
    reputation_provider: ReputationProvider | None = None,
) -> PredictionResult:
    provider = reputation_provider or DisabledReputationProvider()
    direct_url = _safe_direct_url(sample.raw_qr)

    if mode == DetectionMode.DIRECT_URL_ONLY:
        if direct_url is None:
            status, _ = _status_and_message_for_qr(0)
            return _make_prediction(
                sample,
                mode,
                score=0,
                status=status,
                supported=False,
                detected_qr_type=None,
                reasons=["Direct URL payload가 아니어서 이 mode에서는 분석하지 않았습니다."],
            )
        result = analyze_url_with_vt_result(direct_url, DISABLED_REPUTATION)
        return _make_prediction(
            sample,
            mode,
            score=result["final_score"],
            status=result["status"],
            supported=True,
            detected_qr_type="url",
            reasons=result["reasons"],
            extracted_urls=(direct_url,),
            local_url_score=result["final_score"],
        )

    structure = _parse_structure(sample.raw_qr)

    if mode == DetectionMode.STRUCTURE_URL:
        urls = (direct_url,) if direct_url is not None else structure.embedded_urls
        url_results = _analyze_urls(urls, DisabledReputationProvider())
        url_score = max((item["final_score"] for item in url_results), default=0)
        status, _ = _status_and_message_for_qr(url_score)
        reasons = [reason for item in url_results for reason in item["reasons"]]
        return _make_prediction(
            sample,
            mode,
            score=url_score,
            status=status,
            supported=True,
            detected_qr_type=structure.qr_type,
            reasons=reasons,
            extracted_urls=urls,
            embedded_url_max_score=url_score if direct_url is None and url_results else None,
            local_url_score=url_score if url_results else None,
        )

    parent = analyze_non_url_qr(sample.raw_qr) if direct_url is None else None

    if mode == DetectionMode.STRUCTURE_SOCIAL:
        if parent is None:
            score = 0
            detected_qr_type = "url"
            reasons: list[str] = []
            social_score = 0
        else:
            score = int(parent["risk_score"])
            detected_qr_type = parent["qr_type"]
            reasons = list(parent["reasons"])
            social_score = _social_component_score(parent)
        status, _ = _status_and_message_for_qr(score)
        return _make_prediction(
            sample,
            mode,
            score=score,
            status=status,
            supported=True,
            detected_qr_type=detected_qr_type,
            reasons=reasons,
            extracted_urls=structure.embedded_urls,
            parent_score=score,
            social_score=social_score,
        )

    if mode not in {DetectionMode.LOCAL_PROPOSED, DetectionMode.REPUTATION_ASSISTED}:
        raise ValueError(f"unsupported detection mode: {mode}")
    active_provider: ReputationProvider = (
        provider
        if mode == DetectionMode.REPUTATION_ASSISTED
        else DisabledReputationProvider()
    )

    if direct_url is not None:
        url_result = analyze_url_with_vt_result(
            direct_url,
            active_provider.lookup(direct_url),
        )
        return _make_prediction(
            sample,
            mode,
            score=url_result["final_score"],
            status=url_result["status"],
            supported=True,
            detected_qr_type="url",
            reasons=url_result["reasons"],
            extracted_urls=(direct_url,),
            local_url_score=url_result["local_score"],
            reputation_source=(
                active_provider.name
                if url_result.get("vt_available")
                else None
            ),
        )

    parent_score = int(parent["risk_score"])
    urls = structure.embedded_urls
    url_results = _analyze_urls(urls, active_provider)
    embedded_score = max(
        (item["final_score"] for item in url_results),
        default=None,
    )
    score = max(parent_score, embedded_score or 0)
    status, _ = _status_and_message_for_qr(score)
    reasons = list(parent["reasons"])
    if embedded_score is not None and embedded_score >= 30:
        reasons.append("포함 URL의 분석 결과가 최종 위험도에 반영되었습니다.")
    return _make_prediction(
        sample,
        mode,
        score=score,
        status=status,
        supported=True,
        detected_qr_type=parent["qr_type"],
        reasons=reasons,
        extracted_urls=urls,
        parent_score=parent_score,
        embedded_url_max_score=embedded_score,
        social_score=_social_component_score(parent),
        local_url_score=max(
            (int(item["local_score"]) for item in url_results),
            default=None,
        ),
        reputation_source=(
            active_provider.name
            if any(item.get("vt_available") for item in url_results)
            else None
        ),
    )
