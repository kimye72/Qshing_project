from dataclasses import asdict, dataclass, field
from enum import Enum


class DetectionMode(str, Enum):
    DIRECT_URL_ONLY = "direct_url_only"
    STRUCTURE_URL = "structure_url"
    STRUCTURE_SOCIAL = "structure_social"
    LOCAL_PROPOSED = "local_proposed"
    REPUTATION_ASSISTED = "reputation_assisted"


@dataclass(frozen=True)
class EvaluationSample:
    case_id: str
    label: str
    raw_qr: str
    qr_type: str
    scenario: str
    source_type: str
    source_reference: str | None
    attack_features: tuple[str, ...]
    encoding_features: tuple[str, ...]
    split: str
    notes: str | None = None


@dataclass
class PredictionResult:
    case_id: str
    mode: str
    ground_truth: str
    predicted_label: str
    risk_score: int
    status: str
    supported: bool
    qr_type: str
    detected_qr_type: str | None
    scenario: str
    reasons: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0
    parent_score: int | None = None
    embedded_url_max_score: int | None = None
    social_score: int | None = None
    local_url_score: int | None = None
    reputation_source: str | None = None

    def decision_tuple(self) -> tuple:
        """Fields that must remain deterministic across timing repetitions."""
        return (
            self.predicted_label,
            self.risk_score,
            self.status,
            self.supported,
            self.qr_type,
            self.detected_qr_type,
            tuple(self.reasons),
            tuple(self.extracted_urls),
            self.parent_score,
            self.embedded_url_max_score,
            self.social_score,
            self.local_url_score,
            self.reputation_source,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MetricSummary:
    sample_count: int
    evaluated_count: int
    supported_count: int
    unsupported_count: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    specificity: float
    balanced_accuracy: float
    coverage_rate: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TimingSummary:
    count: int
    mean_ms: float
    median_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float

    def to_dict(self) -> dict:
        return asdict(self)
