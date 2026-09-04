import math
import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable

from research.evaluation.models import MetricSummary, PredictionResult, TimingSummary


def _divide(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def calculate_metrics(
    predictions: Iterable[PredictionResult],
    *,
    supported_only: bool = False,
) -> MetricSummary:
    all_predictions = list(predictions)
    evaluated = (
        [item for item in all_predictions if item.supported]
        if supported_only
        else all_predictions
    )
    tp = sum(item.ground_truth == "qshing" and item.predicted_label == "qshing" for item in evaluated)
    tn = sum(item.ground_truth == "benign" and item.predicted_label == "benign" for item in evaluated)
    fp = sum(item.ground_truth == "benign" and item.predicted_label == "qshing" for item in evaluated)
    fn = sum(item.ground_truth == "qshing" and item.predicted_label == "benign" for item in evaluated)
    supported_count = sum(item.supported for item in all_predictions)
    precision = _divide(tp, tp + fp)
    recall = _divide(tp, tp + fn)
    specificity = _divide(tn, tn + fp)

    return MetricSummary(
        sample_count=len(all_predictions),
        evaluated_count=len(evaluated),
        supported_count=supported_count,
        unsupported_count=len(all_predictions) - supported_count,
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        accuracy=_divide(tp + tn, len(evaluated)),
        precision=precision,
        recall=recall,
        f1_score=_divide(2 * precision * recall, precision + recall),
        false_positive_rate=_divide(fp, fp + tn),
        specificity=specificity,
        balanced_accuracy=(recall + specificity) / 2,
        coverage_rate=_divide(supported_count, len(all_predictions)),
    )


def grouped_metrics(
    predictions: Iterable[PredictionResult],
    key: Callable[[PredictionResult], str],
) -> dict[str, MetricSummary]:
    groups: dict[str, list[PredictionResult]] = defaultdict(list)
    for prediction in predictions:
        groups[key(prediction)].append(prediction)
    return {
        group_name: calculate_metrics(items)
        for group_name, items in sorted(groups.items())
    }


def calculate_timing(values_ms: Iterable[float]) -> TimingSummary:
    values = sorted(float(value) for value in values_ms)
    if not values:
        return TimingSummary(0, 0.0, 0.0, 0.0, 0.0, 0.0)
    p95_index = max(0, math.ceil(0.95 * len(values)) - 1)
    return TimingSummary(
        count=len(values),
        mean_ms=statistics.fmean(values),
        median_ms=statistics.median(values),
        p95_ms=values[p95_index],
        min_ms=values[0],
        max_ms=values[-1],
    )
