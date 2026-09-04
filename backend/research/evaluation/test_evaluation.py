import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.evaluation.dataset import DatasetValidationError, load_dataset
from research.evaluation.metrics import calculate_metrics, calculate_timing, grouped_metrics
from research.evaluation.models import DetectionMode, PredictionResult
from research.evaluation.modes import SnapshotReputationProvider, analyze_sample
from research.evaluation.runner import (
    DEFAULT_DATASET,
    RESEARCH_ROOT,
    evaluate,
    write_results,
)


SNAPSHOT_PATH = RESEARCH_ROOT / "data" / "smoke_reputation_snapshot.json"


def _prediction(
    case_id: str,
    truth: str,
    predicted: str,
    *,
    supported: bool = True,
    qr_type: str = "text",
    scenario: str = "test",
) -> PredictionResult:
    return PredictionResult(
        case_id=case_id,
        mode=DetectionMode.LOCAL_PROPOSED.value,
        ground_truth=truth,
        predicted_label=predicted,
        risk_score=70 if predicted == "qshing" else 0,
        status="danger" if predicted == "qshing" else "safe",
        supported=supported,
        qr_type=qr_type,
        detected_qr_type=qr_type,
        scenario=scenario,
    )


class DatasetTests(unittest.TestCase):
    def test_smoke_dataset_loads_with_balanced_labels(self):
        samples = load_dataset(DEFAULT_DATASET)
        self.assertEqual(len(samples), 32)
        self.assertEqual(sum(item.label == "benign" for item in samples), 16)
        self.assertEqual(sum(item.label == "qshing" for item in samples), 16)
        self.assertTrue(all(item.split == "development" for item in samples))

    def test_invalid_label_is_rejected(self):
        invalid = {
            "case_id": "invalid",
            "label": "unknown",
            "raw_qr": "hello",
            "qr_type": "text",
            "scenario": "test",
            "source_type": "synthetic",
            "source_reference": None,
            "attack_features": [],
            "encoding_features": ["none"],
            "split": "development",
            "notes": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.jsonl"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(DatasetValidationError):
                load_dataset(path)

    def test_duplicate_case_id_is_rejected(self):
        valid = {
            "case_id": "duplicate",
            "label": "benign",
            "raw_qr": "hello",
            "qr_type": "text",
            "scenario": "test",
            "source_type": "synthetic",
            "source_reference": None,
            "attack_features": [],
            "encoding_features": ["none"],
            "split": "development",
            "notes": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.jsonl"
            line = json.dumps(valid)
            path.write_text(f"{line}\n{line}\n", encoding="utf-8")
            with self.assertRaises(DatasetValidationError):
                load_dataset(path)


class DetectionModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples = {item.case_id: item for item in load_dataset(DEFAULT_DATASET)}

    def test_m0_supports_direct_url_and_rejects_non_url_coverage(self):
        direct = analyze_sample(
            self.samples["benign_url_https_home"],
            DetectionMode.DIRECT_URL_ONLY,
        )
        non_url = analyze_sample(
            self.samples["q_sms_social_credential"],
            DetectionMode.DIRECT_URL_ONLY,
        )
        self.assertTrue(direct.supported)
        self.assertEqual(direct.predicted_label, "benign")
        self.assertFalse(non_url.supported)
        self.assertEqual(non_url.predicted_label, "benign")

    def test_m1_uses_embedded_url_without_social_score(self):
        url_only = analyze_sample(
            self.samples["q_sms_url_only"],
            DetectionMode.STRUCTURE_URL,
        )
        social_only = analyze_sample(
            self.samples["q_sms_social_credential"],
            DetectionMode.STRUCTURE_URL,
        )
        self.assertEqual(url_only.predicted_label, "qshing")
        self.assertGreaterEqual(url_only.risk_score, 30)
        self.assertEqual(social_only.risk_score, 0)
        self.assertEqual(social_only.predicted_label, "benign")

    def test_m2_uses_social_evidence_without_url_score(self):
        social_only = analyze_sample(
            self.samples["q_sms_social_credential"],
            DetectionMode.STRUCTURE_SOCIAL,
        )
        url_only = analyze_sample(
            self.samples["q_sms_url_only"],
            DetectionMode.STRUCTURE_SOCIAL,
        )
        self.assertEqual(social_only.predicted_label, "qshing")
        self.assertGreaterEqual(social_only.social_score or 0, 30)
        self.assertEqual(url_only.predicted_label, "benign")
        self.assertIsNone(url_only.local_url_score)

    def test_m3_uses_production_max_combination(self):
        sample = self.samples["q_sms_social_safe_url"]
        result = analyze_sample(sample, DetectionMode.LOCAL_PROPOSED)
        self.assertEqual(
            result.risk_score,
            max(result.parent_score or 0, result.embedded_url_max_score or 0),
        )
        self.assertEqual(result.predicted_label, "qshing")

    def test_benign_and_qshing_predictions(self):
        benign = analyze_sample(
            self.samples["benign_sms_daily"],
            DetectionMode.LOCAL_PROPOSED,
        )
        qshing = analyze_sample(
            self.samples["q_text_impersonation_credential"],
            DetectionMode.LOCAL_PROPOSED,
        )
        self.assertEqual(benign.predicted_label, "benign")
        self.assertEqual(qshing.predicted_label, "qshing")

    def test_snapshot_reputation_is_separate_and_reproducible(self):
        provider = SnapshotReputationProvider.from_file(SNAPSHOT_PATH)
        sample = self.samples["q_url_reputation_only"]
        local = analyze_sample(sample, DetectionMode.LOCAL_PROPOSED)
        assisted = analyze_sample(
            sample,
            DetectionMode.REPUTATION_ASSISTED,
            reputation_provider=provider,
        )
        self.assertEqual(local.predicted_label, "benign")
        self.assertEqual(assisted.predicted_label, "qshing")
        self.assertEqual(assisted.reputation_source, "snapshot")

    def test_offline_modes_never_call_network_cache_or_database(self):
        sample = self.samples["q_sms_url_only"]
        with (
            patch("app.services.virustotal.requests.get") as get_mock,
            patch("app.services.virustotal.requests.post") as post_mock,
            patch("app.services.scanner.get_url_report") as vt_mock,
            patch("app.services.url_cache.get_cached_url_analysis") as cache_mock,
            patch("app.services.database._get_table") as table_mock,
        ):
            for mode in (
                DetectionMode.DIRECT_URL_ONLY,
                DetectionMode.STRUCTURE_URL,
                DetectionMode.STRUCTURE_SOCIAL,
                DetectionMode.LOCAL_PROPOSED,
            ):
                analyze_sample(sample, mode)
        get_mock.assert_not_called()
        post_mock.assert_not_called()
        vt_mock.assert_not_called()
        cache_mock.assert_not_called()
        table_mock.assert_not_called()


class MetricsAndRunnerTests(unittest.TestCase):
    def test_confusion_matrix_and_rates(self):
        predictions = [
            _prediction("tp", "qshing", "qshing"),
            _prediction("tn", "benign", "benign"),
            _prediction("fp", "benign", "qshing"),
            _prediction("fn", "qshing", "benign"),
        ]
        result = calculate_metrics(predictions)
        self.assertEqual(
            (
                result.true_positive,
                result.true_negative,
                result.false_positive,
                result.false_negative,
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(result.accuracy, 0.5)
        self.assertEqual(result.precision, 0.5)
        self.assertEqual(result.recall, 0.5)
        self.assertEqual(result.f1_score, 0.5)
        self.assertEqual(result.false_positive_rate, 0.5)
        self.assertEqual(result.specificity, 0.5)

    def test_zero_division_is_deterministic(self):
        result = calculate_metrics([])
        self.assertEqual(result.accuracy, 0.0)
        self.assertEqual(result.precision, 0.0)
        self.assertEqual(result.recall, 0.0)
        self.assertEqual(result.f1_score, 0.0)
        self.assertEqual(result.false_positive_rate, 0.0)
        self.assertEqual(result.coverage_rate, 0.0)

    def test_supported_metrics_and_coverage_are_separate(self):
        predictions = [
            _prediction("supported", "qshing", "qshing"),
            _prediction("unsupported", "qshing", "benign", supported=False),
        ]
        overall = calculate_metrics(predictions)
        supported = calculate_metrics(predictions, supported_only=True)
        self.assertEqual(overall.recall, 0.5)
        self.assertEqual(supported.recall, 1.0)
        self.assertEqual(overall.coverage_rate, 0.5)
        self.assertEqual(supported.coverage_rate, 0.5)

    def test_qr_type_and_scenario_grouping(self):
        predictions = [
            _prediction("sms", "qshing", "qshing", qr_type="sms", scenario="payment"),
            _prediction("url", "benign", "benign", qr_type="url", scenario="normal"),
        ]
        by_type = grouped_metrics(predictions, lambda item: item.qr_type)
        by_scenario = grouped_metrics(predictions, lambda item: item.scenario)
        self.assertEqual(set(by_type), {"sms", "url"})
        self.assertEqual(set(by_scenario), {"normal", "payment"})
        self.assertEqual(by_type["sms"].recall, 1.0)

    def test_timing_summary(self):
        result = calculate_timing([1, 2, 3, 4, 5])
        self.assertEqual(result.mean_ms, 3.0)
        self.assertEqual(result.median_ms, 3.0)
        self.assertEqual(result.p95_ms, 5.0)
        self.assertEqual(result.min_ms, 1.0)
        self.assertEqual(result.max_ms, 5.0)

    def test_runner_generates_all_offline_modes_and_timing_repeats(self):
        samples = load_dataset(DEFAULT_DATASET)
        modes = [
            DetectionMode.DIRECT_URL_ONLY,
            DetectionMode.STRUCTURE_URL,
            DetectionMode.STRUCTURE_SOCIAL,
            DetectionMode.LOCAL_PROPOSED,
        ]
        result = evaluate(samples, modes, timing_repeats=2, warmup=1)
        self.assertEqual(len(result["predictions"]), len(samples) * len(modes))
        self.assertEqual(set(result["modes"]), {mode.value for mode in modes})
        for summary in result["modes"].values():
            self.assertEqual(summary["timing"]["count"], len(samples) * 2)
            self.assertEqual(set(summary["by_qr_type"]), {"url", "sms", "smsto", "mailto", "tel", "wifi", "text"})
            self.assertTrue(summary["by_scenario"])

    def test_machine_readable_results_are_written(self):
        samples = load_dataset(DEFAULT_DATASET)[:2]
        result = evaluate(samples, [DetectionMode.LOCAL_PROPOSED])
        with tempfile.TemporaryDirectory() as directory:
            predictions_path, summary_path = write_results(result, directory)
            self.assertTrue(predictions_path.exists())
            self.assertTrue(summary_path.exists())
            self.assertIn("case_id,mode,ground_truth", predictions_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["dataset"]["sample_count"], 2)
            self.assertNotIn("predictions", summary)


if __name__ == "__main__":
    unittest.main()
