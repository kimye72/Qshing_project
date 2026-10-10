import unittest
from unittest.mock import Mock, patch

import requests
from botocore.exceptions import ReadTimeoutError
from fastapi.testclient import TestClient

from app import main
from app.constants import RULESET_VERSION
from app.schemas import QRAnalyzeRequest, ScanRequest
from app.services import analysis_budget as timing, database, scanner, url_cache, virustotal
from test_analyze_qr import (
    make_cache_item, make_db_result, make_structured_parent_result, make_vt_url_result,
)


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def response(status=200, *, stats=None):
    data = {"id": "offline-report", "attributes": {"last_analysis_stats": stats or {
        "malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 10,
    }}}
    return Mock(status_code=status, json=Mock(return_value={"data": data}))


class SharedBudgetTests(unittest.TestCase):
    def test_reserves_and_monotonic_deadline_are_shared(self):
        clock = FakeClock()
        budget = timing.AnalysisBudget(clock=clock)
        with timing.budget_scope(budget):
            self.assertEqual(sum(timing.io_timeout(3)), 3)
            clock.advance(9.8)
            self.assertAlmostEqual(sum(timing.io_timeout(3)), 0.2)
            clock.advance(0.2)
            with self.assertRaises(timing.AnalysisBudgetExceeded):
                timing.io_timeout(3)
            self.assertAlmostEqual(sum(timing.io_timeout(0.75, storage=True)), 0.75)
            clock.advance(1)
            with self.assertRaises(timing.AnalysisBudgetExceeded):
                timing.io_timeout(0.75, storage=True)
        self.assertIsNone(timing.current_budget())

    def test_scopes_do_not_leak_or_restart_the_enclosing_budget(self):
        clock = FakeClock()
        budget = timing.AnalysisBudget(clock=clock)

        @timing.request_budget
        def operation():
            self.assertIs(timing.current_budget(), budget)
            return {}

        with timing.budget_scope(budget):
            clock.advance(8)
            operation()
            self.assertEqual(budget.remaining(), 4)
            self.assertIs(timing.current_budget(), budget)
        self.assertIsNone(timing.current_budget())

    def test_dynamodb_caps_and_retry_policy_apply_to_both_factories(self):
        with patch.object(database.boto3, "resource") as resource:
            url_cache._get_cache_table()
            cache_config = resource.call_args.kwargs["config"]
            database._get_table()
            storage_config = resource.call_args.kwargs["config"]
        for config, cap in ((cache_config, 0.4), (storage_config, 0.75)):
            self.assertAlmostEqual(config.connect_timeout + config.read_timeout, cap)
            self.assertEqual(config.retries, {"mode": "standard", "total_max_attempts": 1})

    def test_sdk_resource_is_not_created_when_budget_is_insufficient(self):
        clock = FakeClock()
        budget = timing.AnalysisBudget(clock=clock)
        clock.advance(11.1)
        with timing.budget_scope(budget), patch.object(database.boto3, "resource") as resource:
            with self.assertRaises(timing.AnalysisBudgetExceeded):
                url_cache._get_cache_table()
            with self.assertRaises(timing.AnalysisBudgetExceeded):
                database._get_table()
        resource.assert_not_called()


class ReputationBudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.budget = timing.AnalysisBudget(clock=self.clock)
        scope = timing.budget_scope(self.budget)
        scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        settings = (
            patch.object(virustotal, "VIRUSTOTAL_ENABLED", True),
            patch.object(virustotal, "VIRUSTOTAL_API_KEY", "offline-key"),
            patch.object(virustotal, "VIRUSTOTAL_TIMEOUT_SECONDS", 10),
            patch.object(virustotal, "VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", False),
            patch.object(url_cache, "URL_CACHE_ENABLED", False),
            patch.object(database, "DYNAMODB_ENABLED", False),
        )
        for setting in settings:
            setting.start()
            self.addCleanup(setting.stop)
        self.get_patch = patch.object(virustotal.requests, "get", return_value=response(429))
        self.get = self.get_patch.start()
        self.addCleanup(self.get_patch.stop)
        self.post_patch = patch.object(virustotal.requests, "post", side_effect=AssertionError("No live submission"))
        self.post = self.post_patch.start()
        self.addCleanup(self.post_patch.stop)

    def test_slow_vt_timeout_preserves_local_result_and_uses_capped_timeout(self):
        events = []
        original = scanner._get_local_heuristic_score

        def local(*args):
            events.append("local")
            return original(*args)

        def timeout(*args, **kwargs):
            events.append("vt")
            self.clock.advance(sum(kwargs["timeout"]))
            raise requests.Timeout("secret-key internal host")

        self.get.side_effect = timeout
        with patch.object(scanner, "_get_local_heuristic_score", side_effect=local):
            result = scanner.analyze_url("https://wooribank.com")
        self.assertEqual(events, ["local", "vt"])
        self.assertEqual((result["final_score"], result["status"]), (20, "safe"))
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
        self.assertFalse(result["vt_available"])
        self.assertEqual(result["vt_lookup_status"], "timeout")
        self.assertNotIn("secret-key", repr(result))
        self.assertAlmostEqual(sum(self.get.call_args.kwargs["timeout"]), 3)
        self.assertFalse(self.get.call_args.kwargs["allow_redirects"])

    def test_429_failure_and_report_missing_are_not_zero_detection_reports(self):
        for status, expected in ((429, "rate_limited"), (500, "lookup_failed"), (404, "report_missing")):
            with self.subTest(status=status):
                self.get.reset_mock()
                self.get.return_value = response(status)
                result = scanner.analyze_url("https://bit.ly/abc")
                self.assertEqual((result["local_score"], result["final_score"]), (30, 30))
                self.assertFalse(result["vt_available"])
                self.assertEqual(result["vt_lookup_status"], expected)
                self.get.assert_called_once()
                self.post.assert_not_called()

    def test_request_failure_and_invalid_reports_preserve_local_score(self):
        cases = (
            {"side_effect": requests.ConnectionError("secret")},
            {"side_effect": None, "return_value": Mock(status_code=200, json=Mock(side_effect=ValueError("secret")))},
            {"side_effect": None, "return_value": Mock(status_code=200, json=Mock(return_value={"data": {"attributes": {"last_analysis_stats": {}}}}))},
        )
        for options in cases:
            with self.subTest(options=options):
                self.get.configure_mock(**options)
                result = scanner.analyze_url("https://wooribank.com")
                self.assertEqual(result["final_score"], 20)
                self.assertFalse(result["vt_available"])
                self.assertEqual(result["vt_lookup_status"], "lookup_failed")
                self.assertNotIn("secret", repr(result))

    def test_valid_zero_detection_report_is_explicitly_available(self):
        self.get.return_value = response()
        result = scanner.analyze_url("https://wooribank.com")
        self.assertTrue(result["vt_available"])
        self.assertEqual(result["vt_lookup_status"], "available")
        self.assertEqual(result["vt_malicious"], 0)
        self.assertEqual(result["final_score"], 20)

    def test_existing_configuration_gates_and_shorter_vt_timeout_are_respected(self):
        for field, value, expected in (("VIRUSTOTAL_ENABLED", False, "disabled"),
                                        ("VIRUSTOTAL_API_KEY", "", "lookup_failed")):
            with self.subTest(field=field), patch.object(virustotal, field, value):
                result = scanner.analyze_url("https://wooribank.com")
                self.assertEqual(result["vt_lookup_status"], expected)
                self.assertFalse(result["vt_available"])
                self.assertNotIn("VIRUSTOTAL_", repr(result))
        self.get.assert_not_called()
        self.post.assert_not_called()
        with patch.object(virustotal, "VIRUSTOTAL_TIMEOUT_SECONDS", 1):
            scanner.analyze_url("https://wooribank.com")
        self.assertAlmostEqual(sum(self.get.call_args.kwargs["timeout"]), 1)

    def test_no_query_or_submission_starts_after_external_budget_exhaustion(self):
        self.clock.advance(10)
        with patch.object(virustotal, "VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", True):
            result = scanner.analyze_url("https://wooribank.com")
            submission = virustotal.submit_url_for_analysis("https://example.invalid")
        self.assertEqual(result["vt_lookup_status"], "budget_exhausted")
        self.assertEqual(result["final_score"], 20)
        self.assertFalse(submission["available"])
        self.get.assert_not_called()
        self.post.assert_not_called()

    def test_404_submission_reuses_budget_and_does_not_poll(self):
        def missing(*args, **kwargs):
            self.clock.advance(3)
            return response(404)

        self.get.side_effect = missing
        self.post.side_effect = None
        self.post.return_value = Mock(status_code=200, json=Mock(return_value={"data": {"id": "offline-analysis"}}))
        with patch.object(virustotal, "VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", True):
            result = scanner.analyze_url("https://example.invalid")
        self.get.assert_called_once()
        self.post.assert_called_once()
        self.assertAlmostEqual(sum(self.post.call_args.kwargs["timeout"]), 3)
        self.assertEqual(result["vt_lookup_status"], "submitted")
        self.assertFalse(result["vt_available"])
        self.assertEqual(result["vt_score_delta"], 0)

    def test_404_near_deadline_does_not_start_submission(self):
        def missing(*args, **kwargs):
            self.clock.advance(9.98)
            return response(404)

        self.get.side_effect = missing
        with patch.object(virustotal, "VIRUSTOTAL_SUBMIT_IF_NOT_FOUND", True):
            result = scanner.analyze_url("https://example.invalid")
        self.post.assert_not_called()
        self.assertEqual(result["vt_lookup_status"], "budget_exhausted")

    def test_three_urls_use_one_deadline_including_parent_parsing(self):
        timeouts = []
        parent = make_structured_parent_result("sms", [
            "https://one.invalid", "https://bit.ly/abc", "https://wooribank.com",
        ], 55)

        def parse(content):
            self.clock.advance(2)
            return parent

        def slow(*args, **kwargs):
            timeouts.append(sum(kwargs["timeout"]))
            self.clock.advance(timeouts[-1])
            raise requests.Timeout()

        self.get.side_effect = slow
        with patch.object(main, "analyze_non_url_qr", side_effect=parse), patch.object(main, "save_scan_result", return_value=make_db_result()):
            result = main.analyze_qr(QRAnalyzeRequest(content="SMS:recipient:body"))
        self.assertEqual(timeouts, [3, 3, 2])
        self.assertEqual(self.clock.value, 10)
        self.assertEqual(result["risk_score"], 55)
        self.assertEqual(result["embedded_url_max_score"], 30)
        self.assertEqual(result["analyzed_embedded_url_count"], 3)
        self.assertTrue(result["embedded_url_analysis_complete"])
        self.assertTrue(all(item["vt_lookup_status"] == "timeout" for item in result["embedded_url_results"]))

    def test_budget_exhaustion_stops_more_vt_but_preserves_local_api_results(self):
        def slow(*args, **kwargs):
            self.clock.advance(10)
            raise requests.Timeout()

        self.get.side_effect = slow
        with patch.object(main, "save_scan_result", return_value=make_db_result()), TestClient(main.app) as client:
            result = client.post("/analyze-qr", json={
                "content": "확인: https://one.invalid bit.ly/abc wooribank.com extra.invalid",
            }).json()
        self.get.assert_called_once()
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["analyzed_embedded_url_count"], 3)
        self.assertEqual(result["analysis_flags"]["embedded_url_skipped_count"], 1)
        self.assertFalse(result["embedded_url_analysis_complete"])
        self.assertTrue(result["analysis_flags"]["analysis_budget_exhausted"])
        self.assertEqual([item["vt_lookup_status"] for item in result["embedded_url_results"]],
                         ["timeout", "budget_exhausted", "budget_exhausted"])
        assumed = result["embedded_url_results"][1]
        self.assertTrue(assumed["assumed_https"])
        self.assertEqual(assumed["original_candidates"], ["bit.ly/abc"])
        self.assertEqual(assumed["ruleset_version"], RULESET_VERSION)

    def test_local_analysis_failure_uses_failure_list_not_reputation_failure(self):
        original = scanner._get_local_heuristic_score

        def local(url, *args):
            if "failed.invalid" in url:
                raise ValueError("secret internal exception")
            return original(url, *args)

        with patch.object(scanner, "_get_local_heuristic_score", side_effect=local), patch.object(main, "save_scan_result", return_value=make_db_result()), TestClient(main.app) as client:
            response_data = client.post("/analyze-qr", json={
                "content": "확인: bit.ly/abc failed.invalid wooribank.com",
            })
        result = response_data.json()
        self.assertEqual(response_data.status_code, 200)
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["analyzed_embedded_url_count"], 2)
        self.assertFalse(result["embedded_url_analysis_complete"])
        self.assertEqual(result["embedded_url_failures"][0]["error_code"], "EMBEDDED_URL_ANALYSIS_FAILED")
        self.assertNotIn("secret", response_data.text)
        self.assertEqual(self.get.call_count, 2)

    def test_overrunning_socket_call_leaves_later_urls_in_failure_list(self):
        def overrun(*args, **kwargs):
            self.clock.advance(11.5)
            raise requests.Timeout()

        self.get.side_effect = overrun
        with patch.object(main, "save_scan_result", return_value=make_db_result()):
            result = main.analyze_qr(QRAnalyzeRequest(content="확인: bit.ly/abc two.invalid three.invalid"))
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["analyzed_embedded_url_count"], 1)
        self.assertEqual(len(result["embedded_url_failures"]), 2)
        self.assertFalse(result["embedded_url_analysis_complete"])
        self.get.assert_called_once()

    def test_fresh_cache_is_reused_without_vt_and_keeps_ruleset(self):
        item = make_cache_item("https://example.invalid", checked_at=1000,
            **{key: value for key, value in make_vt_url_result("https://example.invalid").items()
               if key in url_cache._CACHE_RESULT_FIELDS})
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(url_cache, "get_cached_url_analysis", return_value=item), patch.object(url_cache, "record_cached_url_scan"):
            result = url_cache.analyze_url_with_cache("https://example.invalid", now_epoch=1000)
        self.get.assert_not_called()
        self.assertTrue(result["cache_hit"])
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
        self.assertEqual(result["vt_lookup_status"], "cached")
        self.assertEqual(result["vt_source"], "cached_report")

    def test_cache_timeout_uses_same_budget_and_preserves_local_result(self):
        table = Mock()
        resource = Mock()
        resource.Table.return_value = table

        def lookup(**kwargs):
            self.clock.advance(10)  # Model an SDK wall-clock overrun, no sleep.
            raise ReadTimeoutError(endpoint_url="offline-cache")

        table.get_item.side_effect = lookup
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(database.boto3, "resource", return_value=resource) as sdk:
            result = url_cache.analyze_url_with_cache("https://wooribank.com", now_epoch=1000)
        config = sdk.call_args.kwargs["config"]
        self.assertAlmostEqual(config.connect_timeout + config.read_timeout, 0.4)
        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["vt_lookup_status"], "budget_exhausted")
        self.assertFalse(result["vt_available"])
        self.get.assert_not_called()
        table.update_item.assert_not_called()

    def test_exhausted_budget_skips_all_cache_and_vt_calls(self):
        self.clock.advance(10)
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(database.boto3, "resource") as resource:
            result = url_cache.analyze_url_with_cache("https://wooribank.com", now_epoch=1000)
        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["vt_lookup_status"], "budget_exhausted")
        resource.assert_not_called()
        self.get.assert_not_called()

    def test_failed_reputation_is_never_cached_as_a_current_success(self):
        cached = make_cache_item("https://wooribank.com", checked_at=1000,
            ruleset_version="1.1", local_score=35, final_score=35, risk_score=35, status="warning")
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(url_cache, "get_cached_url_analysis", return_value=cached), patch.object(url_cache, "record_cached_url_scan"), patch.object(url_cache, "save_cached_url_analysis") as save:
            result = url_cache.analyze_url_with_cache("https://wooribank.com", now_epoch=1000)
        self.assertEqual((result["ruleset_version"], result["final_score"]), (RULESET_VERSION, 20))
        self.assertFalse(result["vt_available"])
        self.assertEqual(result["vt_lookup_status"], "rate_limited")
        self.assertIsNone(save.call_args.kwargs["vt_checked_at"])
        self.assertFalse(save.call_args.args[1]["vt_available"])

    def test_old_submission_cache_is_not_reused_as_zero_detection_report(self):
        cached = make_cache_item("https://example.invalid", checked_at=1000,
            vt_available=True, vt_source="submitted_analysis")
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(url_cache, "get_cached_url_analysis", return_value=cached), patch.object(url_cache, "save_cached_url_analysis"):
            result = url_cache.analyze_url_with_cache("https://example.invalid", now_epoch=1000)
        self.assertFalse(result["cache_hit"])
        self.assertFalse(result["vt_available"])
        self.get.assert_called_once()

    def test_ruleset_change_with_historical_vt_preserves_completed_local_work_after_overrun(self):
        cached = make_cache_item("https://wooribank.com", checked_at=1000,
            ruleset_version="1.1", domain="wooribank.com", local_score=35,
            final_score=100, risk_score=100, status="danger", vt_score_delta=70,
            vt_available=True, vt_source="url_report", vt_malicious=3)

        def overrun(*args, **kwargs):
            self.clock.advance(11.5)
            raise requests.Timeout()

        self.get.side_effect = overrun
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(url_cache, "get_cached_url_analysis", return_value=cached), patch.object(url_cache, "record_cached_url_scan"), patch.object(database.boto3, "resource") as resource, patch.object(scanner, "_get_local_heuristic_score", wraps=scanner._get_local_heuristic_score) as local:
            result = url_cache.analyze_url_with_cache("https://wooribank.com", now_epoch=1000)
        local.assert_called_once()
        resource.assert_not_called()
        self.assertEqual((result["ruleset_version"], result["local_score"]), (RULESET_VERSION, 20))
        self.assertEqual(result["final_score"], 90)
        self.assertFalse(result["vt_available"])
        self.assertEqual(result["vt_lookup_status"], "timeout")
        self.assertEqual(cached["ruleset_version"], "1.1")

    def test_stale_cached_reputation_failure_does_not_refresh_success_timestamp(self):
        cached = make_cache_item("https://example.invalid", checked_at=1000,
            **{key: value for key, value in make_vt_url_result("https://example.invalid", malicious=3).items()
               if key in url_cache._CACHE_RESULT_FIELDS})
        cached["vt_checked_at"] = 900
        self.get.side_effect = requests.Timeout()
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), patch.object(url_cache, "URL_CACHE_FRESHNESS_SECONDS", 10), patch.object(url_cache, "get_cached_url_analysis", return_value=cached), patch.object(url_cache, "record_cached_url_scan"), patch.object(url_cache, "_record_deferred_revalidation"), patch.object(url_cache, "save_cached_url_analysis") as save, patch.object(url_cache, "update_cache_check_time") as refresh:
            result = url_cache.analyze_url_with_cache("https://example.invalid", now_epoch=1100)
        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["vt_lookup_status"], "timeout")
        self.assertEqual(result["vt_source"], "cached_report")
        self.assertFalse(result["vt_available"])
        self.assertTrue(result["analysis_flags"]["historical_reputation_used"])
        self.assertFalse(result["cache_revalidated"])
        self.assertEqual(cached["vt_checked_at"], 900)
        save.assert_not_called()
        refresh.assert_not_called()

    def test_storage_timeout_preserves_completed_api_result(self):
        self.get.side_effect = requests.Timeout()
        table = Mock()
        table.put_item.side_effect = ReadTimeoutError(endpoint_url="offline-storage")
        resource = Mock()
        resource.Table.return_value = table
        with patch.object(database, "DYNAMODB_ENABLED", True), patch.object(database.boto3, "resource", return_value=resource), self.assertLogs(database.logger, level="ERROR"):
            result = main.scan_url(ScanRequest(url="https://wooribank.com"))
        self.assertEqual((result["risk_score"], result["status"]), (20, "safe"))
        self.assertFalse(result["db_saved"])
        self.assertEqual(result["db_error"], "DATABASE_ERROR")
        self.assertNotIn("offline-storage", repr(result))

    def test_storage_is_skipped_without_losing_result_when_reserve_is_reached(self):
        self.clock.advance(11.1)
        with patch.object(database, "DYNAMODB_ENABLED", True), patch.object(database.boto3, "resource") as resource, self.assertLogs(database.logger, level="ERROR"):
            result = main.analyze_qr(QRAnalyzeRequest(content="안녕하세요"))
        resource.assert_not_called()
        self.get.assert_not_called()
        self.assertEqual(result["risk_score"], 0)
        self.assertFalse(result["db_saved"])
        self.assertEqual(result["db_error"], "DATABASE_ERROR")


if __name__ == "__main__":
    unittest.main()
