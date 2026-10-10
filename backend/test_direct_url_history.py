"""Offline consecutive requests through real cache analysis and history storage."""
import copy
import re
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app import main
from app.constants import RULESET_VERSION
from app.schemas import QRAnalyzeRequest, QRAnalyzeResponse, ScanRequest, ScanResponse
from app.services import analysis_budget as timing, database, scanner, url_cache
from test_analysis_budget import FakeClock


def db_error(code="ProvisionedThroughputExceededException"):
    return ClientError({"Error": {"Code": code, "Message": "offline failure"}}, "Write")


class MemoryCacheTable:
    """Apply the service's SET/REMOVE/ADD expressions without an AWS connection."""
    def __init__(self):
        self.items = {}
        self.updates = []
        self.ack_failures = 0

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        item = self.items.get(Key["url_hash"])
        return {"Item": copy.deepcopy(item)} if item else {}

    def update_item(self, **request):
        self.updates.append(copy.deepcopy(request))
        key = request["Key"]["url_hash"]
        names = request["ExpressionAttributeNames"]
        values = request["ExpressionAttributeValues"]
        if "ConditionExpression" in request:
            assert request["ConditionExpression"] == "attribute_exists(#url_hash)"
            if self.ack_failures:
                self.ack_failures -= 1
                raise db_error()
            if key not in self.items:
                raise db_error("ConditionalCheckFailedException")
        item = self.items.setdefault(key, dict(request["Key"]))
        sections = re.split(r"\b(SET|REMOVE|ADD)\b\s*", request["UpdateExpression"])[1:]
        for operation, body in zip(sections[::2], sections[1::2]):
            if operation == "SET":
                for assignment in re.split(r",\s*(?=#)", body.strip()):
                    name, value = assignment.split(" = ", 1)
                    if value.startswith("if_not_exists("):
                        match = re.fullmatch(r"if_not_exists\((#\w+), (:\w+)\)", value)
                        assert match, assignment
                        existing, default = match.groups()
                        item[names[name]] = item.get(names[existing], values[default])
                    else:
                        item[names[name]] = copy.deepcopy(values[value])
            elif operation == "REMOVE":
                for name in body.strip().split(", "):
                    item.pop(names[name], None)
            elif operation == "ADD":
                name, value = body.strip().split()
                item[names[name]] = item.get(names[name], 0) + values[value]
        return {}

    @property
    def acknowledgements(self):
        return [request for request in self.updates if "ConditionExpression" in request]


class MemoryHistoryTable:
    def __init__(self):
        self.items = []
        self.attempts = 0
        self.failures = 0
        self.after_success = None

    def put_item(self, *, Item):
        self.attempts += 1
        if self.failures:
            self.failures -= 1
            raise db_error()
        self.items.append(copy.deepcopy(Item))
        if self.after_success:
            self.after_success()
        return {}


class DirectUrlHistoryTests(unittest.TestCase):
    URL = "https://example.com/"

    def setUp(self):
        self.clock = FakeClock()
        self.cache = MemoryCacheTable()
        self.history = MemoryHistoryTable()
        self.epoch = 1000
        self.configs = []

        def resource(_service, **kwargs):
            self.configs.append(kwargs["config"])

            def table(name):
                if name == url_cache.URL_CACHE_TABLE_NAME:
                    return self.cache
                self.assertEqual(name, database.DYNAMODB_TABLE_NAME)
                return self.history
            return Mock(Table=Mock(side_effect=table))

        patches = (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(url_cache, "URL_CACHE_FRESHNESS_SECONDS", 100),
            patch.object(url_cache, "_utc_epoch_seconds", side_effect=lambda: self.epoch),
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch.object(database.boto3, "resource", side_effect=resource),
            patch.object(scanner, "get_url_report", return_value={
                "enabled": False, "available": False, "lookup_status": "disabled",
            }),
        )
        for active_patch in patches:
            started = active_patch.start()
            if active_patch is patches[-1]:
                self.vt = started
            self.addCleanup(active_patch.stop)

    def direct(self, *, scan=False, before_persist=None):
        budget = timing.AnalysisBudget(clock=self.clock)
        with timing.budget_scope(budget):
            if before_persist is not None:
                result = url_cache.analyze_url_with_cache(self.URL)
                before_persist()
                return main.persist_scan_history(main.ensure_analysis_contract(result))
            if scan:
                result = main.scan_url(ScanRequest(url=self.URL))
                ScanResponse.model_validate(result)
            else:
                result = main.analyze_qr(QRAnalyzeRequest(content=self.URL))
                QRAnalyzeResponse.model_validate(result)
        self.assertFalse(any(key.startswith("_history_") for key in result))
        return result

    def item(self):
        return self.cache.items[url_cache.build_url_hash(self.URL)]

    def test_first_save_failure_then_retry_success_then_duplicate_skip(self):
        self.history.failures = 1
        first = self.direct()
        self.assertFalse(first["db_saved"])
        self.assertFalse(first["history_saved"])
        self.assertEqual(first["db_error"], database.DATABASE_ERROR)
        self.assertFalse(self.item()["direct_history_initialized"])
        self.assertEqual(len(self.cache.acknowledgements), 0)
        second = self.direct(scan=True)
        third = self.direct()
        self.assertTrue(second["cache_hit"])
        self.assertTrue(second["history_saved"])
        self.assertEqual(second["history_event_type"], "initial_analysis")
        self.assertTrue(self.item()["direct_history_initialized"])
        self.assertEqual(third["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(self.history.attempts, 2)
        self.assertEqual(len(self.history.items), 1)
        self.assertEqual(self.item()["scan_count"], 3)
        self.assertEqual(self.vt.call_count, 1)
        self.assertEqual(first["risk_score"], second["risk_score"])
        self.assertEqual(second["ruleset_version"], RULESET_VERSION)

    def test_embedded_cache_then_failed_direct_history_is_retried(self):
        parent = main.analyze_qr(QRAnalyzeRequest(content="확인: example.com/"))
        child = parent["embedded_url_results"][0]
        self.assertTrue(child["assumed_https"])
        self.assertEqual(child["original_url"], "example.com/")
        self.assertEqual(child["original_candidates"], ["example.com/"])
        self.assertEqual(child["analysis_url"], self.URL)
        self.assertEqual(len(self.history.items), 1)
        self.assertEqual(self.history.items[0]["qr_type"], "text_with_url")
        self.assertEqual(len(self.cache.acknowledgements), 0)
        self.assertFalse(self.item()["direct_history_initialized"])
        self.assertNotIn("scan_count", self.item())
        self.history.failures = 1
        first = self.direct()
        self.assertFalse(first["history_saved"])
        self.assertFalse(self.item()["direct_history_initialized"])
        second = self.direct()
        third = self.direct()
        self.assertTrue(second["history_saved"])
        self.assertEqual(third["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.history.items), 2)
        self.assertEqual(self.history.attempts, 3)
        self.assertEqual(self.item()["scan_count"], 3)
        self.assertEqual(self.vt.call_count, 1)
        self.assertNotIn("assumed_https", self.item())
        self.assertNotIn("original_url", self.item())
        self.assertNotIn("original_candidates", self.item())

    def test_db_success_ack_failure_preserves_success_and_may_duplicate(self):
        self.cache.ack_failures = 1
        first = self.direct()
        self.assertTrue(first["db_saved"])
        self.assertTrue(first["history_saved"])
        self.assertIsNone(first["db_error"])
        self.assertFalse(self.item()["direct_history_initialized"])
        second = self.direct()
        third = self.direct()
        self.assertTrue(second["history_saved"])
        self.assertEqual(len(self.history.items), 2)
        self.assertEqual(third["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.cache.acknowledgements), 2)

    def test_first_history_skipped_for_budget_is_retried_next_request(self):
        first = self.direct(before_persist=lambda: self.clock.advance(11.1))
        self.assertFalse(first["db_saved"])
        self.assertFalse(self.item()["direct_history_initialized"])
        self.assertEqual(self.history.attempts, 0)
        self.assertEqual(len(self.cache.acknowledgements), 0)
        second = self.direct()
        self.assertTrue(second["history_saved"])
        self.assertEqual(len(self.history.items), 1)

    def test_ack_budget_exhaustion_preserves_saved_history_without_new_call(self):
        self.history.after_success = lambda: self.clock.advance(10.1)
        first = self.direct()
        self.assertTrue(first["db_saved"])
        self.assertTrue(first["history_saved"])
        self.assertTrue(first["analysis_flags"]["analysis_budget_exhausted"])
        self.assertFalse(self.item()["direct_history_initialized"])
        self.assertEqual(len(self.cache.acknowledgements), 0)
        self.history.after_success = None
        second = self.direct()
        self.assertTrue(second["history_saved"])
        self.assertEqual(len(self.history.items), 2)
        self.assertEqual(len(self.cache.acknowledgements), 1)

    def test_missing_legacy_completion_flag_retries_then_skips(self):
        self.direct()
        del self.item()["direct_history_initialized"]
        second = self.direct()
        third = self.direct()
        self.assertTrue(second["history_saved"])
        self.assertEqual(second["history_event_type"], "initial_analysis")
        self.assertEqual(third["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.history.items), 2)

    def test_confirmed_legacy_completion_flag_skips_unchanged_history(self):
        self.direct()
        second = self.direct()
        self.assertEqual(second["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(self.history.attempts, 1)
        self.assertEqual(len(self.cache.acknowledgements), 1)
        for config in self.configs:
            self.assertEqual(config.retries["total_max_attempts"], 1)
            self.assertLessEqual(config.connect_timeout + config.read_timeout, 0.75)

    def test_risk_change_still_saves_history_then_skips_same_result(self):
        self.direct()
        self.epoch += 101
        self.vt.return_value = {
            "enabled": True, "available": True, "source": "url_report",
            "lookup_status": "available", "stats": {
                "malicious": 3, "suspicious": 0, "harmless": 0, "undetected": 10,
            },
        }
        with patch.object(url_cache, "_virustotal_is_configured", return_value=True):
            changed = self.direct()
        unchanged = self.direct()
        self.assertEqual(changed["history_event_type"], "risk_changed")
        self.assertTrue(changed["history_saved"])
        self.assertEqual(changed["status"], "danger")
        self.assertEqual(changed["risk_score"], 80)
        self.assertEqual(unchanged["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.history.items), 2)

    def test_ruleset_risk_change_saves_reclassified_history(self):
        self.direct()
        self.item().update({
            "ruleset_version": "1.1", "local_score": 35, "risk_score": 35,
            "final_score": 35, "status": "warning",
        })
        changed = self.direct()
        unchanged = self.direct()
        self.assertTrue(changed["history_saved"])
        self.assertEqual(changed["history_event_type"], "ruleset_reclassified")
        self.assertEqual(changed["ruleset_version"], RULESET_VERSION)
        self.assertEqual(changed["risk_score"], 10)
        self.assertEqual(unchanged["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.history.items), 2)

    def test_ruleset_change_without_risk_change_keeps_duplicate_policy(self):
        self.direct()
        self.item()["ruleset_version"] = "1.1"
        changed = self.direct()
        self.assertEqual(changed["ruleset_version"], RULESET_VERSION)
        self.assertEqual(changed["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(len(self.history.items), 1)

    def test_missing_cache_ack_does_not_create_metadata_only_item(self):
        url_cache.mark_direct_url_history_saved(self.URL)
        self.assertEqual(self.cache.items, {})

    def test_overlapping_requests_can_save_duplicate_initial_histories(self):
        # Both requests read pending state before either persists; there is no
        # cross-table transaction/claim. This test records that deliberate limit.
        first = url_cache.analyze_url_with_cache(self.URL)
        second = url_cache.analyze_url_with_cache(self.URL)
        self.assertFalse(self.item()["direct_history_initialized"])
        self.assertEqual(self.item()["scan_count"], 2)
        first = main.persist_scan_history(first)
        second = main.persist_scan_history(second)
        self.assertTrue(first["history_saved"])
        self.assertTrue(second["history_saved"])
        self.assertEqual(len(self.history.items), 2)
        self.assertEqual(self.direct()["history_skip_reason"], "duplicate_unchanged")

    def test_real_api_serializes_failure_retry_and_duplicate_skip(self):
        self.history.failures = 1
        with TestClient(main.app) as client:
            first = client.post("/analyze-qr", json={"content": self.URL})
            second = client.post("/scan", json={"url": self.URL})
            third = client.post("/analyze-qr", json={"content": self.URL})
        for response in (first, second, third):
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("_history_cache_url", response.text)
            self.assertNotIn("offline failure", response.text)
            self.assertEqual(response.json()["ruleset_version"], RULESET_VERSION)
        self.assertFalse(first.json()["history_saved"])
        self.assertTrue(second.json()["history_saved"])
        self.assertEqual(third.json()["history_skip_reason"], "duplicate_unchanged")


if __name__ == "__main__":
    unittest.main()
