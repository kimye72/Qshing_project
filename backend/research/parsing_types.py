from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ParserResult:
    """Common, research-only output shared by both parser strategies."""

    qr_type: str | None
    body: str | None = None
    subject: str | None = None
    recipient: str | None = None
    extracted_urls: tuple[str, ...] = ()
    extracted_url_candidates: tuple[str, ...] = ()
    parse_success: bool = True

    def to_dict(self) -> dict:
        result = asdict(self)
        result["extracted_urls"] = list(self.extracted_urls)
        result["extracted_url_candidates"] = list(
            self.extracted_url_candidates
        )
        return result


@dataclass(frozen=True)
class ParsingCase:
    """Manually specified expected structure for one deterministic case."""

    case_id: str
    description: str
    raw_qr: str
    expected_qr_type: str
    expected_body: str | None = None
    expected_subject: str | None = None
    expected_recipient: str | None = None
    expected_urls: tuple[str, ...] = ()
    expected_url_candidates: tuple[str, ...] = ()


@dataclass(frozen=True)
class ComparisonResult:
    """Exact-match measurements for one parser and one case."""

    parse_success: bool
    qr_type_exact_match: bool
    body_exact_match: bool
    subject_exact_match: bool
    recipient_exact_match: bool
    extracted_url_exact_match: bool
    expected_url_count: int
    actual_url_count: int
    url_count_match: bool
    url_query_preservation: bool
    url_candidate_exact_match: bool
    exact_success: bool

    def to_dict(self) -> dict:
        return asdict(self)

