"""Bounded, complete history traversal with mock DynamoDB and a fake clock."""
import copy
import unittest
from decimal import Decimal
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app import main
from app.services import analysis_budget as timing, database
from test_analysis_budget import FakeClock
from test_analyze_qr import make_url_result


def record(scan_id, day=1, status="safe", **fields):
    return {
        "scan_id": scan_id, "created_at": f"2026-10-{day:02d}T00:00:00+00:00",
        "status": status, "risk_score": Decimal("10"), **fields,
    }


def page(items=(), key=None, scanned=None):
    response = {"Items": list(items), "ScannedCount": len(items) if scanned is None else scanned}
    if key is not None:
        response["LastEvaluatedKey"] = {"scan_id": key}
    return response


class PagesTable:
    def __init__(self, pages, after_scan=None):
        self.pages = pages
        self.calls = []
        self.after_scan = after_scan

    def scan(self, **kwargs):
        index = len(self.calls)
        self.calls.append(kwargs)
        response = self.pages[index]
        if isinstance(response, Exception):
            raise response
        if self.after_scan:
            self.after_scan()
        return copy.deepcopy(response)


class ScanHistoryReadTests(unittest.TestCase):
    def setUp(self):
        self.table = PagesTable([page()])
        for active_patch in (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch.object(database, "_get_table", side_effect=lambda: self.table),
            patch.object(main, "ADMIN_API_KEY", "offline-admin"),
        ):
            active_patch.start()
            self.addCleanup(active_patch.stop)

    def api(self, path="/scans"):
        with TestClient(main.app) as client:
            return client.get(path, headers={"X-Admin-Key": "offline-admin"})

    def assert_unavailable(self, code, path="/scans"):
        response = self.api(path)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(set(response.json()), {"detail", "error_code"})
        self.assertEqual(response.json()["error_code"], code)
        self.assertNotIn("private-", response.text)
        return response

    def test_latest_record_on_later_page_not_first_scan_limit(self):
        self.table = PagesTable([page([record("old", 1)], "cursor"), page([record("new", 10)])])
        history = database.get_recent_scan_history(limit=1)
        self.assertEqual([item["scan_id"] for item in history["items"]], ["new"])
        self.assertEqual(history["metadata"]["pages_read"], 2)
        self.assertEqual(history["metadata"]["evaluated_items"], 2)
        self.assertEqual(history["metadata"]["requested_limit"], 1)
        self.assertEqual(self.table.calls[0]["Limit"], database.HISTORY_PAGE_EVALUATION_LIMIT)
        self.assertEqual(self.table.calls[1]["ExclusiveStartKey"], {"scan_id": "cursor"})
        self.assertTrue(all(call["ConsistentRead"] for call in self.table.calls))

    def test_empty_filtered_page_continues_and_finds_newest_matching_rows(self):
        self.table = PagesTable([
            page(key="empty", scanned=200),
            page([record("old-danger", 1, "danger")], "more", scanned=20),
            page([record("new-danger", 10, "danger")], scanned=30),
        ])
        history = database.get_recent_scan_history(limit=1, status="danger")
        self.assertEqual([item["scan_id"] for item in history["items"]], ["new-danger"])
        self.assertEqual(len(self.table.calls), 3)
        self.assertEqual(history["metadata"]["evaluated_items"], 250)
        self.assertEqual(history["metadata"]["matching_records_count"], 2)
        self.assertEqual(history["metadata"]["scope"], "latest_saved_history_for_status")
        self.assertEqual(history["metadata"]["status_filter"], "danger")
        self.assertTrue(all("FilterExpression" in call for call in self.table.calls))

    def test_fewer_matching_records_than_limit_is_a_complete_result(self):
        self.table = PagesTable([page([record("match", 2, "warning")], "next", 50), page(scanned=20)])
        response = self.api("/scans?limit=10&status=warning")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["metadata"]["returned_count"], 1)
        self.assertTrue(result["metadata"]["query_complete"])

    def test_same_time_order_is_stable_across_page_order(self):
        for ids in (("a", "z"), ("z", "a")):
            with self.subTest(ids=ids):
                self.table = PagesTable([page([record(ids[0])], "next"), page([record(ids[1])])])
                self.assertEqual([item["scan_id"] for item in database.list_scan_results()], ["z", "a"])

    def test_timezone_offsets_sort_chronologically(self):
        self.table = PagesTable([page([
            record("earlier", created_at="2026-10-11T10:00:00+09:00"),
            record("later", created_at="2026-10-11T02:00:00Z"),
        ])])
        self.assertEqual([item["scan_id"] for item in database.list_scan_results()], ["later", "earlier"])

    def test_empty_table_is_successful_and_distinct_from_disabled_database(self):
        summary = database.get_scan_summary()
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["recent_items"], [])
        self.assertTrue(summary["metadata"]["query_complete"])
        self.assertEqual(summary["metadata"]["aggregated_count"], 0)
        with patch.object(database, "DYNAMODB_ENABLED", False), patch.object(database, "_get_table") as factory:
            self.assert_unavailable("SCAN_HISTORY_DISABLED")
            self.assert_unavailable("SCAN_HISTORY_DISABLED", "/scans/summary")
        factory.assert_not_called()

    def test_legacy_missing_analysis_fields_preserve_unknown_details(self):
        self.table = PagesTable([page([{"scan_id": "legacy", "created_at": "2020-01-01T00:00:00Z"}, record("dated", 2)])])
        response = self.api()
        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertEqual([item["scan_id"] for item in history["items"]], ["dated", "legacy"])
        legacy = history["items"][1]
        self.assertFalse(legacy["embedded_url_details_available"])
        self.assertIsNone(legacy["embedded_url_analysis_complete"])
        self.assertIsNone(legacy["embedded_url_results"])
        self.assertEqual(legacy["created_at"], "2020-01-01T00:00:00Z")

    def test_unorderable_matching_record_does_not_become_a_normal_latest_result(self):
        for created_at in (None, "", "invalid-time", 123):
            with self.subTest(created_at=created_at):
                self.table = PagesTable([page([record("known", 10), record("undated", created_at=created_at)])])
                self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")

    def test_duplicate_page_items_do_not_duplicate_lists_or_summary(self):
        shared = record("shared", 4, "danger", vt_malicious=Decimal("2"))
        pages = [page([shared], "next"), page([shared, record("other", 2, "warning")])]
        self.table = PagesTable(pages)
        history = database.get_recent_scan_history()
        self.assertEqual(len(history["items"]), 2)
        self.assertEqual(history["metadata"]["evaluated_items"], 3)
        self.table = PagesTable(pages)
        summary = database.get_scan_summary()
        self.assertEqual((summary["total"], summary["danger"], summary["warning"]), (2, 1, 1))
        self.assertEqual(summary["vt_malicious_total"], 2)

    def test_exact_legacy_copies_without_id_are_deduplicated(self):
        old = {"created_at": "2020-01-01T00:00:00Z", "risk_score": Decimal("0")}
        self.table = PagesTable([page([old], "next"), page([dict(reversed(list(old.items())))])])
        self.assertEqual(len(database.list_scan_results()), 1)

    def test_conflicting_duplicate_id_does_not_return_arbitrary_copy(self):
        self.table = PagesTable([page([record("same")], "next"), page([record("same", status="danger")])])
        self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")

    def test_repeated_cursor_stops_without_partial_response(self):
        self.table = PagesTable([page([record("old")], "same"), page(key="same")])
        self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")
        self.assertEqual(len(self.table.calls), 2)

    def test_cursor_cycle_is_detected(self):
        self.table = PagesTable([page(key="a"), page(key="b"), page(key="a")])
        self.assert_unavailable("SCAN_HISTORY_INCOMPLETE", "/scans/summary")
        self.assertEqual(len(self.table.calls), 3)

    def test_intermediate_sdk_failure_is_not_an_empty_or_partial_success(self):
        error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "private-credential ARN"}}, "Scan")
        for path in ("/scans", "/scans/summary"):
            with self.subTest(path=path):
                self.table = PagesTable([page([record("partial")], "next"), error])
                self.assert_unavailable("SCAN_HISTORY_READ_FAILED", path)
                self.assertEqual(len(self.table.calls), 2)

    def test_page_cap_stops_but_exactly_complete_boundary_is_allowed(self):
        with patch.object(database, "HISTORY_MAX_PAGES", 2):
            self.table = PagesTable([page(key="a"), page(key="b")])
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")
            self.assertEqual(len(self.table.calls), 2)
            self.table = PagesTable([page(key="a"), page([record("final")])])
            self.assertEqual(len(database.list_scan_results()), 1)

    def test_evaluated_item_cap_counts_filtered_out_rows_and_clamps_next_page(self):
        with patch.object(database, "HISTORY_MAX_EVALUATED_ITEMS", 3), patch.object(database, "HISTORY_PAGE_EVALUATION_LIMIT", 2):
            self.table = PagesTable([page(key="a", scanned=2), page(key="b", scanned=1)])
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")
            self.assertEqual([call["Limit"] for call in self.table.calls], [2, 1])
            self.table = PagesTable([page(key="a", scanned=2), page(scanned=1)])
            self.assertEqual(database.list_scan_results(), [])

    def test_time_exhausted_after_page_stops_before_additional_call(self):
        clock = FakeClock()
        self.table = PagesTable([page([record("partial")], "next")], after_scan=lambda: clock.advance(8.1))
        with timing.budget_scope(timing.AnalysisBudget(clock=clock, seconds=8)):
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")
        self.assertEqual(len(self.table.calls), 1)

    def test_final_page_that_overruns_deadline_is_not_returned_as_complete(self):
        clock = FakeClock()
        self.table = PagesTable([page([record("final")])], after_scan=lambda: clock.advance(7.1))
        with timing.budget_scope(timing.AnalysisBudget(clock=clock, seconds=8)):
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE", "/scans/summary")

    def test_resource_construction_exhaustion_prevents_scan_start(self):
        clock = FakeClock()

        def factory():
            clock.advance(7.1)
            return self.table
        with timing.budget_scope(timing.AnalysisBudget(clock=clock, seconds=8)), patch.object(database, "_get_table", side_effect=factory):
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE")
        self.assertEqual(self.table.calls, [])

    def test_shared_deadline_reduces_each_page_sdk_timeouts(self):
        clock = FakeClock()
        configs, budgets = [], []
        self.table = PagesTable([page(key="next"), page()])
        self.table.after_scan = lambda: clock.advance(6.8 if len(self.table.calls) == 1 else 0.05)

        def resource(_service, **kwargs):
            configs.append(kwargs["config"])
            budgets.append(timing.current_budget())
            return Mock(Table=Mock(return_value=self.table))
        # Exercise the real factory's SDK Config without an AWS connection.
        with timing.budget_scope(timing.AnalysisBudget(clock=clock, seconds=8)):
            with patch.object(database, "_get_table", self.real_table_factory), patch.object(database.boto3, "resource", side_effect=resource):
                summary = database.get_scan_summary()
        self.assertEqual(summary["total"], 0)
        self.assertIs(budgets[0], budgets[1])
        self.assertAlmostEqual(configs[0].connect_timeout + configs[0].read_timeout, 0.75)
        self.assertAlmostEqual(configs[1].connect_timeout + configs[1].read_timeout, 0.2)
        self.assertTrue(all(config.retries["total_max_attempts"] == 1 for config in configs))

    def test_summary_aggregation_does_not_start_a_new_budget(self):
        clock = FakeClock()

        class SlowNumber(int):
            def __int__(self):
                clock.advance(0.6)
                return 1
        self.table = PagesTable([page([record("row", vt_malicious=SlowNumber(1))])], after_scan=lambda: clock.advance(6.8))
        with timing.budget_scope(timing.AnalysisBudget(clock=clock, seconds=8)):
            self.assert_unavailable("SCAN_HISTORY_INCOMPLETE", "/scans/summary")

    def test_missing_evaluation_count_fails_closed(self):
        self.table = PagesTable([{"Items": []}])
        self.assert_unavailable("SCAN_HISTORY_READ_FAILED")

    def test_latest_n_and_summary_share_scope_and_parent_vt_totals(self):
        child = main._embedded_url_response(make_url_result("https://example.com"), {
            "original_url": "example.com", "original_candidates": ["example.com"],
            "analysis_url": "https://example.com", "assumed_https": True,
        })
        child["vt_malicious"] = 99
        pages = [page([record("old", 1, "warning", vt_malicious=99)], "next"), page([
            record("new-danger", 10, "danger", vt_malicious=2, embedded_url_results=[child], embedded_url_failures=[], embedded_url_analysis_complete=True, embedded_url_policy_version="2.0"),
            record("new-safe", 9, "safe"), record("new-unknown", 8, None, vt_malicious=1, vt_suspicious=1),
        ])]
        self.table = PagesTable(pages)
        history = self.api("/scans?limit=3").json()
        self.table = PagesTable(pages)
        response = self.api("/scans/summary?limit=3")
        self.assertEqual(response.status_code, 200)
        summary = response.json()
        self.assertEqual(summary["recent_items"], history["items"])
        self.assertEqual((summary["total"], summary["safe"], summary["warning"], summary["danger"], summary["unknown"]), (3, 1, 0, 1, 1))
        self.assertEqual((summary["vt_malicious_total"], summary["vt_suspicious_total"]), (3, 1))
        self.assertEqual(summary["metadata"]["aggregated_count"], 3)
        self.assertEqual(summary["metadata"]["matching_records_count"], 4)
        self.assertEqual(summary["metadata"]["vt_totals_scope"], "parent_history_records")
        self.assertEqual(summary["metadata"]["count_unit"], "stored_history_records")
        restored = history["items"][0]["embedded_url_results"][0]
        self.assertTrue(restored["assumed_https"])
        self.assertEqual(restored["original_candidates"], ["example.com"])
        self.assertEqual(restored["vt_malicious"], 99)
        self.assertEqual(history["items"][0]["vt_malicious"], 2)

    def test_recent_items_is_preview_of_same_aggregate_set(self):
        self.table = PagesTable([page([record(str(day), day) for day in range(1, 13)])])
        summary = database.get_scan_summary(limit=12)
        self.assertEqual(summary["total"], 12)
        self.assertEqual(len(summary["recent_items"]), 10)
        self.assertEqual(summary["recent_items"][0]["scan_id"], "12")
        self.assertEqual(summary["metadata"]["recent_items_limit"], 10)

    def test_authentication_still_blocks_before_database_access(self):
        with TestClient(main.app) as client:
            for path in ("/scans", "/scans/summary"):
                self.assertEqual(client.get(path).status_code, 401)
                self.assertEqual(client.get(path, headers={"X-Admin-Key": "wrong"}).status_code, 403)
        self.assertEqual(self.table.calls, [])

    def test_openapi_documents_success_metadata_and_read_errors(self):
        schema = main.app.openapi()
        for path in ("/scans", "/scans/summary"):
            responses = schema["paths"][path]["get"]["responses"]
            self.assertIn("503", responses)
            self.assertIn("200", responses)
        properties = schema["components"]["schemas"]["ScanHistoryMetadata"]["properties"]
        self.assertIn("requested_limit", properties)
        self.assertIn("query_complete", properties)


# Save the real factory before any per-test patch is installed.
ScanHistoryReadTests.real_table_factory = staticmethod(database._get_table)


if __name__ == "__main__":
    unittest.main()
