import argparse
import csv
import json
import statistics
import time
from collections import Counter
from pathlib import Path

from research.evaluation.dataset import VALID_SPLITS, load_dataset
from research.evaluation.metrics import calculate_metrics, calculate_timing, grouped_metrics
from research.evaluation.models import DetectionMode, EvaluationSample, PredictionResult
from research.evaluation.modes import (
    DisabledReputationProvider,
    ReputationProvider,
    SnapshotReputationProvider,
    analyze_sample,
)


RESEARCH_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = RESEARCH_ROOT / "data" / "smoke_qshing_dataset.jsonl"
OFFLINE_MODES = (
    DetectionMode.DIRECT_URL_ONLY,
    DetectionMode.STRUCTURE_URL,
    DetectionMode.STRUCTURE_SOCIAL,
    DetectionMode.LOCAL_PROPOSED,
)


def _serialize_grouped_metrics(metrics: dict) -> dict:
    return {name: value.to_dict() for name, value in metrics.items()}


def evaluate(
    samples: list[EvaluationSample],
    modes: list[DetectionMode],
    *,
    timing_repeats: int = 1,
    warmup: int = 0,
    reputation_provider: ReputationProvider | None = None,
) -> dict:
    if timing_repeats < 1:
        raise ValueError("timing_repeats must be at least 1")
    if warmup < 0:
        raise ValueError("warmup must not be negative")

    all_predictions: list[PredictionResult] = []
    summaries: dict[str, dict] = {}
    provider = reputation_provider or DisabledReputationProvider()

    for mode in modes:
        mode_predictions: list[PredictionResult] = []
        timing_values: list[float] = []
        for sample in samples:
            for _ in range(warmup):
                analyze_sample(sample, mode, reputation_provider=provider)

            first_prediction: PredictionResult | None = None
            expected_decision: tuple | None = None
            sample_timings: list[float] = []
            for _ in range(timing_repeats):
                started = time.perf_counter_ns()
                prediction = analyze_sample(
                    sample,
                    mode,
                    reputation_provider=provider,
                )
                elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                sample_timings.append(elapsed_ms)
                timing_values.append(elapsed_ms)
                if first_prediction is None:
                    first_prediction = prediction
                    expected_decision = prediction.decision_tuple()
                elif prediction.decision_tuple() != expected_decision:
                    raise RuntimeError(
                        f"non-deterministic result for {sample.case_id} in {mode.value}"
                    )

            assert first_prediction is not None
            first_prediction.analysis_time_ms = statistics.median(sample_timings)
            mode_predictions.append(first_prediction)

        overall = calculate_metrics(mode_predictions)
        supported_only = calculate_metrics(mode_predictions, supported_only=True)
        summaries[mode.value] = {
            "overall": overall.to_dict(),
            "supported_only": supported_only.to_dict(),
            "by_qr_type": _serialize_grouped_metrics(
                grouped_metrics(mode_predictions, lambda item: item.qr_type)
            ),
            "by_scenario": _serialize_grouped_metrics(
                grouped_metrics(mode_predictions, lambda item: item.scenario)
            ),
            "timing": calculate_timing(timing_values).to_dict(),
            "false_positive_case_ids": [
                item.case_id
                for item in mode_predictions
                if item.ground_truth == "benign" and item.predicted_label == "qshing"
            ],
            "false_negative_case_ids": [
                item.case_id
                for item in mode_predictions
                if item.ground_truth == "qshing" and item.predicted_label == "benign"
            ],
        }
        all_predictions.extend(mode_predictions)

    dataset_summary = {
        "sample_count": len(samples),
        "label_counts": dict(sorted(Counter(item.label for item in samples).items())),
        "qr_type_counts": dict(sorted(Counter(item.qr_type for item in samples).items())),
        "scenario_counts": dict(sorted(Counter(item.scenario for item in samples).items())),
        "split_counts": dict(sorted(Counter(item.split for item in samples).items())),
        "source_type_counts": dict(sorted(Counter(item.source_type for item in samples).items())),
    }
    return {
        "dataset": dataset_summary,
        "configuration": {
            "modes": [mode.value for mode in modes],
            "timing_repeats": timing_repeats,
            "warmup": warmup,
            "cache_policy": "disabled_by_pure_research_adapter",
            "network_policy": "offline_no_external_requests",
            "reputation_provider": provider.name,
        },
        "modes": summaries,
        "predictions": all_predictions,
    }


def write_results(result: dict, output_dir: str | Path) -> tuple[Path, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    predictions_path = output_path / "predictions.csv"
    summary_path = output_path / "summary.json"

    predictions: list[PredictionResult] = result["predictions"]
    if predictions:
        rows = [prediction.to_dict() for prediction in predictions]
        for row in rows:
            row["reasons"] = json.dumps(row["reasons"], ensure_ascii=False)
            row["extracted_urls"] = json.dumps(
                row["extracted_urls"],
                ensure_ascii=False,
            )
        with predictions_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    serializable_summary = {
        key: value
        for key, value in result.items()
        if key != "predictions"
    }
    with summary_path.open("w", encoding="utf-8") as summary_file:
        json.dump(serializable_summary, summary_file, ensure_ascii=False, indent=2)
        summary_file.write("\n")
    return predictions_path, summary_path


def print_summary(result: dict) -> None:
    dataset = result["dataset"]
    print(
        f"Dataset: {dataset['sample_count']} samples "
        f"(benign={dataset['label_counts'].get('benign', 0)}, "
        f"qshing={dataset['label_counts'].get('qshing', 0)})"
    )
    print(
        "Mode                  Accuracy Precision Recall   F1       FPR      Coverage"
    )
    for mode_name, summary in result["modes"].items():
        metric = summary["overall"]
        print(
            f"{mode_name:<21} "
            f"{metric['accuracy']:<8.4f} "
            f"{metric['precision']:<9.4f} "
            f"{metric['recall']:<8.4f} "
            f"{metric['f1_score']:<8.4f} "
            f"{metric['false_positive_rate']:<8.4f} "
            f"{metric['coverage_rate']:.4f}"
        )
    print()
    print("Mode                  Mean ms  Median ms P95 ms   Min ms   Max ms")
    for mode_name, summary in result["modes"].items():
        timing = summary["timing"]
        print(
            f"{mode_name:<21} "
            f"{timing['mean_ms']:<8.4f} "
            f"{timing['median_ms']:<9.4f} "
            f"{timing['p95_ms']:<8.4f} "
            f"{timing['min_ms']:<8.4f} "
            f"{timing['max_ms']:.4f}"
        )
    print()
    for mode_name, summary in result["modes"].items():
        print(f"{mode_name} FP: {summary['false_positive_case_ids'] or ['none']}")
        print(f"{mode_name} FN: {summary['false_negative_case_ids'] or ['none']}")


def _selected_modes(mode_name: str, *, include_reputation: bool) -> list[DetectionMode]:
    if mode_name == "all":
        selected = list(OFFLINE_MODES)
    else:
        selected = [DetectionMode(mode_name)]
    if include_reputation and DetectionMode.REPUTATION_ASSISTED not in selected:
        selected.append(DetectionMode.REPUTATION_ASSISTED)
    return selected


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run deterministic Qshing detection ablation evaluation.",
    )
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument(
        "--mode",
        choices=["all", *(mode.value for mode in DetectionMode)],
        default="all",
        help="'all' runs the four offline modes; reputation is opt-in.",
    )
    parser.add_argument(
        "--split",
        choices=["all", *sorted(VALID_SPLITS)],
        default="all",
    )
    parser.add_argument("--timing-repeats", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--output-dir")
    parser.add_argument("--reputation-snapshot")
    parser.add_argument("--include-reputation", action="store_true")
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    modes = _selected_modes(args.mode, include_reputation=args.include_reputation)
    needs_reputation = DetectionMode.REPUTATION_ASSISTED in modes
    if needs_reputation and not args.reputation_snapshot:
        parser.error("reputation-assisted mode requires --reputation-snapshot")

    provider: ReputationProvider = (
        SnapshotReputationProvider.from_file(args.reputation_snapshot)
        if args.reputation_snapshot
        else DisabledReputationProvider()
    )
    samples = load_dataset(
        args.dataset,
        split=None if args.split == "all" else args.split,
    )
    result = evaluate(
        samples,
        modes,
        timing_repeats=args.timing_repeats,
        warmup=args.warmup,
        reputation_provider=provider,
    )
    print_summary(result)
    if args.output_dir:
        predictions_path, summary_path = write_results(result, args.output_dir)
        print(f"Predictions: {predictions_path}")
        print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
