"""Store/read real analysis output through a mocked DynamoDB round trip."""
import copy
import json
import unittest
from decimal import Decimal
from unittest.mock import patch
from urllib.parse import quote

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from fastapi.testclient import TestClient

from app import main
from app.constants import EMBEDDED_URL_POLICY_VERSION, RULESET_VERSION
from app.schemas import EmbeddedUrlFailure, EmbeddedUrlResult, QRAnalyzeRequest
from app.services import database, scanner, url_cache


class RoundTripTable:
    def __init__(self):
        self.items = []
        self.put_count = 0
        self.scans = []

    def put_item(self, *, Item):
        self.put_count += 1
        # Real DynamoDB codecs catch unsupported floats and reproduce the
        # Decimal values returned by boto3, including inside lists and maps.
        wire = TypeSerializer().serialize(Item)
        self.items.append(TypeDeserializer().deserialize(wire))
        return {}

    def scan(self, **kwargs):
        self.scans.append(kwargs)
        return {"Items": copy.deepcopy(self.items)}


class EmbeddedUrlHistoryTests(unittest.TestCase):
    EXPLICIT = "https://example.com/Case?Token=AbC&x=0"
    CANDIDATE = "bit.ly/3abcde"

    def setUp(self):
        self.table = RoundTripTable()
        patches = (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch.object(database, "_get_table", return_value=self.table),
            patch.object(url_cache, "URL_CACHE_ENABLED", False),
            patch.object(main, "ADMIN_API_KEY", "offline-admin"),
            patch.object(scanner, "get_url_report", side_effect=self.report),
        )
        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)

    @staticmethod
    def report(url):
        if url.startswith("https://example.com/"):
            return {
                "enabled": True, "available": True, "source": "url_report",
                "lookup_status": "available", "stats": {
                    "malicious": 1, "suspicious": 0, "harmless": 7, "undetected": 2,
                },
            }
        return {
            "enabled": True, "available": False, "lookup_status": "rate_limited",
        }

    def analyze_and_list(self, content):
        with TestClient(main.app) as client:
            analyzed = client.post("/analyze-qr", json={"content": content})
            listed = client.get("/scans?limit=20", headers={"X-Admin-Key": "offline-admin"})
        self.assertEqual(analyzed.status_code, 200)
        self.assertTrue(analyzed.json()["db_saved"])
        self.assertEqual(listed.status_code, 200)
        analysis = analyzed.json()
        history = next(item for item in listed.json()["items"]
                       if item["scan_id"] == analysis["scan_id"])
        return analysis, history

    def test_storage_projection_matches_existing_public_models(self):
        self.assertEqual(set(database._EMBEDDED_URL_RESULT_FIELDS),
                         set(EmbeddedUrlResult.model_fields))
        self.assertEqual(set(database._EMBEDDED_URL_FAILURE_FIELDS),
                         set(EmbeddedUrlFailure.model_fields))

    def test_sms_and_text_results_survive_store_list_and_api_json(self):
        body = f"확인: {self.EXPLICIT} {self.CANDIDATE}"
        contents = (
            ("sms", "SMS:+821012345678?body=" + quote(body, safe="")),
            ("text_with_url", body),
        )
        for qr_type, content in contents:
            with self.subTest(qr_type=qr_type):
                before = self.table.put_count
                analysis, history = self.analyze_and_list(content)
                self.assertEqual(self.table.put_count, before + 1)
                self.assertEqual(history["qr_type"], qr_type)
                self.assertTrue(history["embedded_url_details_available"])
                self.assertEqual(history["embedded_url_results"], analysis["embedded_url_results"])
                self.assertEqual(history["embedded_url_failures"], [])
                self.assertTrue(history["embedded_url_analysis_complete"])
                self.assertEqual(history["embedded_url_policy_version"], EMBEDDED_URL_POLICY_VERSION)
                self.assertEqual(history["embedded_url_count"], 2)
                self.assertEqual(history["analyzed_embedded_url_count"], 2)
                self.assertEqual(history["embedded_url_max_score"], 55)
                self.assertEqual(history["final_score"], max(analysis["text_score"], 55))
                self.assertEqual(history["ruleset_version"], RULESET_VERSION)
                explicit, candidate = history["embedded_url_results"]
                self.assertEqual(explicit["original_url"], self.EXPLICIT)
                self.assertEqual(explicit["analysis_url"], self.EXPLICIT)
                self.assertEqual(explicit["original_candidates"], [])
                self.assertFalse(explicit["assumed_https"])
                self.assertEqual(candidate["original_url"], self.CANDIDATE)
                self.assertEqual(candidate["original_candidates"], [self.CANDIDATE])
                self.assertEqual(candidate["analysis_url"], "https://" + self.CANDIDATE)
                self.assertTrue(candidate["assumed_https"])
                self.assertEqual((explicit["local_score"], explicit["vt_score_delta"], explicit["final_score"]),
                                 (10, 45, 55))
                self.assertEqual((candidate["local_score"], candidate["vt_score_delta"], candidate["final_score"]),
                                 (30, 0, 30))
                self.assertTrue(explicit["vt_available"])
                self.assertEqual((explicit["vt_lookup_status"], explicit["vt_source"], explicit["vt_malicious"]),
                                 ("available", "url_report", 1))
                self.assertFalse(candidate["vt_available"])
                self.assertEqual(candidate["vt_lookup_status"], "rate_limited")
                self.assertIsNone(candidate["vt_source"])
                self.assertEqual(candidate["vt_malicious"], 0)
                self.assertFalse(history["vt_available"])
                self.assertEqual(history["vt_score_delta"], 0)
                self.assertEqual(history["vt_malicious"], 0)
                for child in history["embedded_url_results"]:
                    EmbeddedUrlResult.model_validate(child)
                json.dumps(history, ensure_ascii=False, allow_nan=False)

    def test_partial_failure_and_three_url_limit_are_preserved(self):
        content = f"확인: {self.EXPLICIT} fail.example/ {self.CANDIDATE} extra.example/"

        def analyze(url):
            if url == "https://fail.example/":
                raise RuntimeError("private-exception credential=secret-value")
            return scanner.analyze_url(url)

        with patch.object(main, "analyze_url", side_effect=analyze) as analyzer:
            analysis, history = self.analyze_and_list(content)
        self.assertEqual(analyzer.call_count, 3)
        self.assertEqual(self.table.put_count, 1)
        self.assertEqual(history["embedded_url_results"], analysis["embedded_url_results"])
        self.assertEqual(history["embedded_url_failures"], analysis["embedded_url_failures"])
        self.assertEqual(history["embedded_url_count"], 4)
        self.assertEqual(history["analyzed_embedded_url_count"], 2)
        self.assertEqual(history["embedded_url_max_score"], 55)
        self.assertFalse(history["embedded_url_analysis_complete"])
        self.assertEqual(history["analysis_flags"]["embedded_url_failed_count"], 1)
        self.assertEqual(history["analysis_flags"]["embedded_url_skipped_count"], 1)
        failure = history["embedded_url_failures"][0]
        self.assertEqual(failure["original_url"], "fail.example/")
        self.assertEqual(failure["analysis_url"], "https://fail.example/")
        self.assertTrue(failure["assumed_https"])
        self.assertEqual(failure["error_code"], "EMBEDDED_URL_ANALYSIS_FAILED")
        self.assertEqual(set(failure), set(EmbeddedUrlFailure.model_fields))
        EmbeddedUrlFailure.model_validate(failure)
        self.assertNotIn("private-exception", repr(self.table.items))
        self.assertNotIn("secret-value", json.dumps(history))

    def test_allowlist_excludes_private_fields_raw_payload_and_failure_scores(self):
        result = main.analyze_non_url_qr("확인: example.com/")
        result = main.analyze_text_with_embedded_urls(result)
        child = result["embedded_url_results"][0]
        child.update({
            "raw_result": {"virustotal": {"api_key": "private-key"}},
            "_history_should_save": True, "_history_cache_url": "private-cache-key",
            "exception": "private-exception", "credentials": "private-credentials",
        })
        child["analysis_flags"].update({
            "credentials": {"token": "private-token"},
            "shortener": {"exception": "private-nested-error"},
        })
        failure = {
            "original_url": "fail.example/", "original_candidates": ["fail.example/"],
            "analysis_url": "https://fail.example/", "assumed_https": True,
            "error_code": "EMBEDDED_URL_ANALYSIS_FAILED", "risk_score": 100,
            "vt_available": True, "vt_malicious": 99, "exception": "private-exception",
        }
        result["embedded_url_failures"] = [failure]
        result["embedded_url_analysis_complete"] = False
        original = copy.deepcopy(result)
        saved = database.save_scan_result(main.ensure_analysis_contract(result))
        self.assertTrue(saved["saved"])
        stored = self.table.items[0]
        loaded = database._make_dashboard_item(stored)
        self.assertEqual(set(loaded["embedded_url_results"][0]), set(EmbeddedUrlResult.model_fields))
        self.assertEqual(set(loaded["embedded_url_failures"][0]), set(EmbeddedUrlFailure.model_fields))
        self.assertNotIn("shortener", loaded["embedded_url_results"][0]["analysis_flags"])
        self.assertNotIn("private-", repr(stored))
        self.assertNotIn("private-", json.dumps(loaded))
        self.assertEqual(result["embedded_url_results"], original["embedded_url_results"])
        self.assertEqual(result["embedded_url_failures"], original["embedded_url_failures"])

    def test_decimal_false_zero_empty_lists_and_cache_metadata_round_trip(self):
        result = main.analyze_non_url_qr("확인: example.com/")
        result = main.analyze_text_with_embedded_urls(result)
        child = result["embedded_url_results"][0]
        child.update({
            "vt_available": False, "vt_lookup_status": "timeout", "vt_source": None,
            "vt_malicious": Decimal("0"), "vt_suspicious": Decimal("0"),
            "vt_harmless": Decimal("0"), "vt_undetected": Decimal("0"),
            "vt_score_delta": Decimal("0"), "cache_hit": True,
            "cache_age_seconds": Decimal("0"), "cache_revalidated": False,
            "revalidation_reason": "stale_cache", "reasons": [], "original_candidates": [],
            "analysis_flags": {
                "non_https": False, "explicit_port": None,
                "hostname_label_count": Decimal("2"), "analysis_budget_exhausted": False,
            },
        })
        database.save_scan_result(main.ensure_analysis_contract(result))
        stored = self.table.items[0]["embedded_url_results"][0]
        self.assertIsInstance(stored["cache_age_seconds"], Decimal)
        loaded = database.list_scan_results()[0]
        restored = json.loads(json.dumps(loaded))["embedded_url_results"][0]
        self.assertIs(restored["vt_available"], False)
        self.assertEqual(restored["vt_lookup_status"], "timeout")
        self.assertIsNone(restored["vt_source"])
        self.assertEqual(restored["vt_malicious"], 0)
        self.assertIs(restored["cache_hit"], True)
        self.assertEqual(restored["cache_age_seconds"], 0)
        self.assertIs(restored["cache_revalidated"], False)
        self.assertEqual(restored["revalidation_reason"], "stale_cache")
        self.assertEqual(restored["original_candidates"], [])
        self.assertEqual(restored["reasons"], [])
        self.assertEqual(restored["analysis_flags"], child["analysis_flags"])
        self.assertEqual(loaded["embedded_url_failures"], [])

    def test_legacy_missing_details_are_unknown_even_when_summary_exists(self):
        for count in (0, 2):
            with self.subTest(count=count):
                old = {
                    "scan_id": "old-id", "qr_type": "sms", "embedded_url_count": Decimal(count),
                    "analyzed_embedded_url_count": Decimal(count), "embedded_url_max_score": Decimal("55"),
                    "risk_score": Decimal("55"), "status": "warning",
                    "analysis_flags": {"embedded_url_analysis_complete": True},
                }
                self.table.items = [old]
                loaded = database.list_scan_results()[0]
                self.assertFalse(loaded["embedded_url_details_available"])
                self.assertIsNone(loaded["embedded_url_results"])
                self.assertIsNone(loaded["embedded_url_failures"])
                self.assertIsNone(loaded["embedded_url_analysis_complete"])
                self.assertIsNone(loaded["embedded_url_policy_version"])
                self.assertEqual(loaded["embedded_url_count"], count)
                json.dumps(loaded, allow_nan=False)

    def test_partial_legacy_metadata_does_not_invent_completion_or_reputation(self):
        old = {
            "embedded_url_results": [], "embedded_url_analysis_complete": False,
            "embedded_url_policy_version": "1.0",
        }
        loaded = database._make_dashboard_item(old)
        self.assertEqual(loaded["embedded_url_results"], [])
        self.assertIsNone(loaded["embedded_url_failures"])
        self.assertFalse(loaded["embedded_url_analysis_complete"])
        self.assertEqual(loaded["embedded_url_policy_version"], "1.0")
        self.assertFalse(loaded["embedded_url_details_available"])
        # Provided partial children retain only what was actually stored.
        old["embedded_url_results"] = [{"analysis_url": self.EXPLICIT}]
        loaded = database._make_dashboard_item(old)
        self.assertEqual(loaded["embedded_url_results"], [{"analysis_url": self.EXPLICIT}])

    def test_legacy_scans_api_serializes_unknown_detail_as_null(self):
        self.table.items = [{"scan_id": "legacy", "embedded_url_count": Decimal("1")}]
        with TestClient(main.app) as client:
            response = client.get("/scans", headers={"X-Admin-Key": "offline-admin"})
        self.assertEqual(response.status_code, 200)
        item = response.json()["items"][0]
        self.assertFalse(item["embedded_url_details_available"])
        self.assertIsNone(item["embedded_url_results"])
        self.assertIsNone(item["embedded_url_failures"])
        self.assertIsNone(item["embedded_url_analysis_complete"])
        self.assertIsNone(item["embedded_url_policy_version"])

    def test_zero_detection_report_is_distinct_from_unavailable_reputation(self):
        def reputation(url):
            report = self.report(url)
            if report.get("available"):
                report["stats"]["malicious"] = 0
            return report
        with patch.object(scanner, "get_url_report", side_effect=reputation):
            _, history = self.analyze_and_list(f"확인: {self.EXPLICIT} {self.CANDIDATE}")
        available, unavailable = history["embedded_url_results"]
        self.assertEqual((available["vt_malicious"], unavailable["vt_malicious"]), (0, 0))
        self.assertTrue(available["vt_available"])
        self.assertEqual(available["vt_lookup_status"], "available")
        self.assertFalse(unavailable["vt_available"])
        self.assertEqual(unavailable["vt_lookup_status"], "rate_limited")
        self.assertEqual((available["final_score"], unavailable["final_score"]), (10, 30))

    def test_no_url_qr_is_distinct_from_missing_legacy_detail(self):
        for content in ("안녕하세요", "tel:01012345678", "WIFI:T:nopass;S:Demo;;"):
            with self.subTest(content=content):
                analysis, history = self.analyze_and_list(content)
                self.assertEqual(history["embedded_url_count"], 0)
                self.assertEqual(history["analyzed_embedded_url_count"], 0)
                self.assertIsNone(history["embedded_url_max_score"])
                self.assertTrue(history["embedded_url_details_available"])
                self.assertEqual(history["embedded_url_results"], [])
                self.assertEqual(history["embedded_url_failures"], [])
                self.assertTrue(history["embedded_url_analysis_complete"])
                self.assertEqual(history["risk_score"], analysis["risk_score"])

    def test_direct_url_history_keeps_parent_scores_and_has_no_child_history(self):
        analysis, history = self.analyze_and_list(self.EXPLICIT)
        self.assertEqual(self.table.put_count, 1)
        self.assertEqual(history["qr_type"], "url")
        self.assertEqual(history["url"], self.EXPLICIT)
        self.assertEqual(history["final_score"], analysis["final_score"])
        self.assertTrue(history["vt_available"])
        self.assertEqual(history["vt_malicious"], 1)
        self.assertEqual(history["embedded_url_results"], [])
        self.assertEqual(history["embedded_url_failures"], [])
        self.assertTrue(history["embedded_url_analysis_complete"])
        self.assertTrue(history["embedded_url_details_available"])

    def test_existing_empty_parent_flags_are_not_replaced_from_raw_result(self):
        loaded = database._make_dashboard_item({
            "analysis_flags": {}, "raw_result": {"analysis_flags": {"embedded_url_skipped_count": 9}},
        })
        self.assertEqual(loaded["analysis_flags"], {})

    def test_read_projection_also_removes_unexpected_nested_private_fields(self):
        loaded = database._make_dashboard_item({
            "embedded_url_results": [{
                "analysis_url": self.EXPLICIT, "raw_result": {"token": "private-token"},
                "analysis_flags": {"non_https": False, "credentials": "private-token"},
            }],
            "embedded_url_failures": [{
                "analysis_url": "https://fail.example/", "error_code": "EMBEDDED_URL_ANALYSIS_FAILED",
                "risk_score": 0, "vt_available": True, "exception": "private-exception",
            }],
        })
        self.assertNotIn("private-", json.dumps(loaded))
        self.assertNotIn("risk_score", loaded["embedded_url_failures"][0])
        self.assertNotIn("vt_available", loaded["embedded_url_failures"][0])
        self.assertIsNone(loaded["embedded_url_analysis_complete"])


if __name__ == "__main__":
    unittest.main()
