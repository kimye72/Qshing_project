import unittest
from decimal import Decimal
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main
from app.schemas import QRAnalyzeRequest, QRAnalyzeResponse, ScanRequest, ScanResponse
from app.services import database, url_cache
from app.services.qr_analyzer import analyze_non_url_qr
from app.services.scanner import analyze_url


def make_url_result(url: str) -> dict:
    return {
        "url": url,
        "domain": "example.com",
        "decoded_url": None,
        "qr_type": "url",
        "contains_url": True,
        "extracted_urls": [url],
        "local_score": 10,
        "vt_score_delta": 0,
        "final_score": 10,
        "risk_score": 10,
        "ruleset_version": "1.0",
        "status": "safe",
        "message": "현재 기준으로는 비교적 안전한 URL입니다.",
        "reasons": ["특별한 위험 요소가 발견되지 않았습니다."],
        "analysis_flags": {},
        "vt_available": False,
        "vt_source": None,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 0,
        "vt_undetected": 0,
        "raw_result": {},
    }


def make_scored_url_result(url: str, score: int) -> dict:
    result = make_url_result(url)
    status = "danger" if score >= 70 else "warning" if score >= 30 else "safe"
    result.update(
        {
            "local_score": score,
            "final_score": score,
            "risk_score": score,
            "status": status,
            "message": f"URL score {score}",
        }
    )
    return result


def make_text_with_url_result(urls: list[str], score: int) -> dict:
    status = "danger" if score >= 70 else "warning" if score >= 30 else "safe"
    return {
        "qr_type": "text_with_url",
        "raw_content_preview": "안내 텍스트",
        "contains_url": True,
        "extracted_urls": list(urls),
        "url": urls[0] if urls else None,
        "domain": "example.com" if urls else None,
        "risk_score": score,
        "status": status,
        "message": f"Text score {score}",
        "reasons": [
            "일반 텍스트 안에 URL이 포함되어 있습니다. 포함된 URL 분석이 필요합니다."
        ],
        "analysis_flags": {"contains_url": True},
        "raw_result": {"qr_type": "text_with_url"},
    }


def make_db_result() -> dict:
    return {
        "saved": True,
        "scan_id": "test-scan-id",
        "created_at": "2026-01-01T00:00:00+00:00",
        "date": "2026-01-01",
        "error": None,
    }


def make_vt_url_result(
    url: str,
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 1,
) -> dict:
    result = make_url_result(url)
    detected = malicious + suspicious
    if malicious >= 3 or detected >= 5:
        delta = 70
    elif malicious >= 1 or suspicious >= 2:
        delta = 45
    elif suspicious == 1:
        delta = 25
    else:
        delta = 0

    final_score = min(result["local_score"] + delta, 100)
    status = "danger" if final_score >= 70 else "warning" if final_score >= 30 else "safe"
    result.update(
        {
            "vt_score_delta": delta,
            "final_score": final_score,
            "risk_score": final_score,
            "status": status,
            "vt_available": True,
            "vt_source": "url_report",
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_harmless": harmless,
            "vt_undetected": 10,
        }
    )
    return result


def make_cache_item(url: str, *, checked_at: int, **updates) -> dict:
    result = make_url_result(url)
    result.update(updates)
    item = {
        "url_hash": url_cache.build_url_hash(url),
        "domain": result["domain"],
        "local_score": result["local_score"],
        "vt_score_delta": result["vt_score_delta"],
        "final_score": result["final_score"],
        "risk_score": result["risk_score"],
        "status": result["status"],
        "message": result["message"],
        "reasons": result["reasons"],
        "analysis_flags": result["analysis_flags"],
        "ruleset_version": result["ruleset_version"],
        "vt_available": result["vt_available"],
        "vt_source": result["vt_source"],
        "vt_malicious": result["vt_malicious"],
        "vt_suspicious": result["vt_suspicious"],
        "vt_harmless": result["vt_harmless"],
        "vt_undetected": result["vt_undetected"],
        "analyzed_at": checked_at,
        "last_checked_at": checked_at,
    }
    if "direct_history_initialized" in updates:
        item["direct_history_initialized"] = updates[
            "direct_history_initialized"
        ]
    return item


class AnalyzeQrRoutingTests(unittest.TestCase):
    def setUp(self):
        cache_disabled = patch.object(url_cache, "URL_CACHE_ENABLED", False)
        cache_disabled.start()
        self.addCleanup(cache_disabled.stop)

    def call_with_url_mock(self, content: str):
        with (
            patch("app.main.analyze_url", side_effect=make_url_result) as url_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()) as db_mock,
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        url_mock.assert_called_once()
        db_mock.assert_called_once()
        response_data = QRAnalyzeResponse.model_validate(result).model_dump()
        for field in (
            "local_score",
            "vt_score_delta",
            "final_score",
            "ruleset_version",
            "vt_available",
            "cache_hit",
            "cache_revalidated",
        ):
            self.assertIn(field, response_data)
        return result, url_mock.call_args.args[0]

    def test_https_url_uses_url_analyzer(self):
        result, analyzed_url = self.call_with_url_mock("https://example.com")
        self.assertEqual(analyzed_url, "https://example.com")
        self.assertEqual(result["qr_type"], "url")
        self.assertTrue(result["contains_url"])
        self.assertEqual(result["risk_score"], result["final_score"])
        self.assertEqual(result["local_score"], 10)
        self.assertEqual(result["vt_score_delta"], 0)
        self.assertEqual(result["ruleset_version"], "1.0")

    def test_http_url_keeps_existing_score_policy(self):
        with patch(
            "app.services.scanner.get_url_report",
            return_value={"enabled": False, "available": False},
        ):
            result = analyze_url("http://example.com")

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["local_score"], 30)
        self.assertEqual(result["vt_score_delta"], 0)
        self.assertEqual(result["final_score"], 30)
        self.assertEqual(result["status"], "warning")

    def test_vt_score_components_preserve_existing_clamp(self):
        with (
            patch(
                "app.services.scanner._get_local_heuristic_score",
                return_value=(60, [], {}),
            ),
            patch(
                "app.services.scanner.get_url_report",
                return_value={
                    "enabled": True,
                    "available": True,
                    "stats": {"malicious": 3, "suspicious": 0},
                },
            ),
        ):
            result = analyze_url("https://example.com")

        self.assertEqual(result["local_score"], 60)
        self.assertEqual(result["vt_score_delta"], 70)
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["final_score"], 100)

    def test_uppercase_https_url_uses_url_analyzer(self):
        _, analyzed_url = self.call_with_url_mock("HTTPS://example.com")
        self.assertEqual(analyzed_url, "HTTPS://example.com")

    def test_outer_whitespace_is_removed(self):
        result, analyzed_url = self.call_with_url_mock("   https://example.com   ")
        self.assertEqual(analyzed_url, "https://example.com")
        self.assertEqual(result["raw_content_preview"], "https://example.com")

    def test_encoded_full_url_uses_decoded_url_analyzer(self):
        encoded = "%68%74%74%70%73%3A%2F%2Fexample.com/login"
        result, analyzed_url = self.call_with_url_mock(encoded)

        self.assertEqual(analyzed_url, "https://example.com/login")
        self.assertEqual(result["raw_content_preview"], encoded)
        self.assertEqual(result["extracted_urls"], ["https://example.com/login"])

    def test_encoded_full_url_uses_decoded_url_cache_identity(self):
        encoded = "%68%74%74%70%73%3A%2F%2Fexample.com/login"
        analysis_url = "https://example.com/login"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            main.analyze_qr(QRAnalyzeRequest(content=encoded))

        self.assertEqual(cache_mock.call_args.args[0], analysis_url)
        self.assertEqual(
            url_cache.build_url_hash(cache_mock.call_args.args[0]),
            url_cache.build_url_hash(analysis_url),
        )

    def test_missing_hostname_is_client_error(self):
        with self.assertRaises(HTTPException) as raised:
            main.analyze_qr(QRAnalyzeRequest(content="https://"))

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "유효하지 않은 HTTP(S) URL입니다.")

    def test_whitespace_only_content_is_client_error(self):
        with self.assertRaises(HTTPException) as raised:
            main.analyze_qr(QRAnalyzeRequest(content="     "))

        self.assertEqual(raised.exception.status_code, 400)

    def test_plain_text_keeps_non_url_analysis(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content="안녕하세요"))

        cache_mock.assert_not_called()
        db_mock.assert_called_once()
        self.assertEqual(result["qr_type"], "text")
        self.assertFalse(result["contains_url"])
        self.assertEqual(result["vt_score_delta"], 0)
        self.assertEqual(result["risk_score"], result["final_score"])
        self.assertEqual(result["ruleset_version"], "1.0")

    def _analyze_embedded_scores(
        self,
        *,
        text_score: int,
        url_scores: list[int],
    ):
        urls = [f"https://example{i}.com/login" for i in range(len(url_scores))]
        result_by_url = {
            url: make_scored_url_result(url, score)
            for url, score in zip(urls, url_scores)
        }
        with (
            patch(
                "app.main.analyze_non_url_qr",
                return_value=make_text_with_url_result(urls, text_score),
            ),
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: result_by_url[url],
            ) as cache_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="안내: " + " ".join(urls))
            )
        return result, cache_mock, db_mock

    def test_embedded_url_keeps_text_with_url_parent_type(self):
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="안내: https://example.com/login")
            )

        cache_mock.assert_called_once()
        self.assertEqual(
            cache_mock.call_args.kwargs["analysis_context"],
            "embedded",
        )
        db_mock.assert_called_once()
        self.assertEqual(result["qr_type"], "text_with_url")
        self.assertTrue(result["contains_url"])
        self.assertEqual(result["risk_score"], 15)
        self.assertEqual(result["text_score"], 15)
        self.assertEqual(result["embedded_url_max_score"], 10)

    def test_text_score_wins_over_safe_embedded_url(self):
        result, cache_mock, db_mock = self._analyze_embedded_scores(
            text_score=20,
            url_scores=[10],
        )

        self.assertEqual(result["final_score"], 20)
        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["local_score"], 20)
        self.assertEqual(result["vt_score_delta"], 0)
        self.assertEqual(result["embedded_url_max_score"], 10)
        cache_mock.assert_called_once()
        db_mock.assert_called_once()

    def test_dangerous_embedded_url_sets_parent_danger(self):
        result, _, db_mock = self._analyze_embedded_scores(
            text_score=20,
            url_scores=[80],
        )

        self.assertEqual(result["final_score"], 80)
        self.assertEqual(result["status"], "danger")
        self.assertIn(
            "포함된 URL 분석에서 높은 위험도가 탐지되었습니다.",
            result["reasons"],
        )
        db_mock.assert_called_once()

    def test_dangerous_text_wins_over_safe_embedded_url(self):
        result, _, _ = self._analyze_embedded_scores(
            text_score=70,
            url_scores=[10],
        )

        self.assertEqual(result["text_score"], 70)
        self.assertEqual(result["embedded_url_max_score"], 10)
        self.assertEqual(result["final_score"], 70)
        self.assertEqual(result["status"], "danger")

    def test_two_embedded_urls_use_max_score(self):
        result, cache_mock, _ = self._analyze_embedded_scores(
            text_score=20,
            url_scores=[10, 55],
        )

        self.assertEqual(result["embedded_url_max_score"], 55)
        self.assertEqual(result["final_score"], 55)
        self.assertEqual(cache_mock.call_count, 2)

    def test_three_embedded_urls_use_max_score(self):
        result, cache_mock, _ = self._analyze_embedded_scores(
            text_score=20,
            url_scores=[10, 30, 80],
        )

        self.assertEqual(result["embedded_url_max_score"], 80)
        self.assertEqual(result["final_score"], 80)
        self.assertEqual(result["analyzed_embedded_url_count"], 3)
        self.assertEqual(cache_mock.call_count, 3)

    def test_more_than_three_embedded_urls_are_limited(self):
        urls = [f"https://example{i}.com" for i in range(4)]
        with (
            patch(
                "app.main.analyze_non_url_qr",
                return_value=make_text_with_url_result(urls, 20),
            ),
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="안내: " + " ".join(urls))
            )

        self.assertEqual(result["embedded_url_count"], 4)
        self.assertEqual(result["analyzed_embedded_url_count"], 3)
        self.assertEqual(len(result["extracted_urls"]), 4)
        self.assertEqual(cache_mock.call_count, 3)

    def test_duplicate_embedded_url_is_analyzed_once(self):
        url = "https://example.com/login"
        with (
            patch(
                "app.main.analyze_non_url_qr",
                return_value=make_text_with_url_result([url, url, url], 20),
            ),
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda value, **_: make_url_result(value),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content=f"안내: {url} {url} {url}")
            )

        self.assertEqual(result["extracted_urls"], [url, url, url])
        self.assertEqual(result["embedded_url_count"], 1)
        self.assertEqual(result["analyzed_embedded_url_count"], 1)
        cache_mock.assert_called_once()

    def test_embedded_analysis_failure_returns_text_result(self):
        url = "https://example.com"
        with (
            patch(
                "app.main.analyze_non_url_qr",
                return_value=make_text_with_url_result([url], 45),
            ),
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=RuntimeError("internal failure"),
            ),
            patch("app.main.logger.warning") as log_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content=f"안내: {url}")
            )

        self.assertEqual(result["text_score"], 45)
        self.assertEqual(result["final_score"], 45)
        self.assertEqual(result["analyzed_embedded_url_count"], 0)
        self.assertEqual(result["embedded_url_results"], [])
        log_mock.assert_called_once()
        db_mock.assert_called_once()

    def test_malformed_embedded_url_does_not_fail_parent(self):
        with patch(
            "app.main.save_scan_result",
            return_value=make_db_result(),
        ) as db_mock:
            result = main.analyze_qr(
                QRAnalyzeRequest(content="안내: http://[::1")
            )

        self.assertEqual(result["qr_type"], "text_with_url")
        self.assertEqual(result["final_score"], result["text_score"])
        self.assertEqual(result["analyzed_embedded_url_count"], 0)
        db_mock.assert_called_once()

    def test_vt_disabled_uses_local_embedded_url_score(self):
        with (
            patch(
                "app.services.scanner.get_url_report",
                return_value={"enabled": False, "available": False},
            ),
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="안내: https://example.com")
            )

        self.assertEqual(result["embedded_url_max_score"], 10)
        self.assertEqual(result["embedded_url_results"][0]["vt_score_delta"], 0)
        self.assertFalse(result["embedded_url_results"][0]["vt_available"])

    def test_embedded_cache_then_direct_scan_preserves_direct_initial_history(self):
        url = "https://example.com"
        state = {"item": None}

        def get_cached(_url):
            return dict(state["item"]) if state["item"] else None

        def save_cached(value, analysis_result, **kwargs):
            now = kwargs["now_epoch"]
            item = make_cache_item(value, checked_at=now)
            item["direct_history_initialized"] = kwargs.get(
                "direct_history_initialized"
            )
            if kwargs.get("increment_scan"):
                item.update(
                    {
                        "scan_count": 1,
                        "first_seen_at": now,
                        "last_scanned_at": now,
                    }
                )
            state["item"] = item

        def record_scan(_url_hash, *, scanned_at):
            state["item"]["scan_count"] = state["item"].get("scan_count", 0) + 1
            state["item"].setdefault("first_seen_at", scanned_at)
            state["item"]["last_scanned_at"] = scanned_at
            state["item"]["direct_history_initialized"] = True

        with (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                side_effect=get_cached,
            ),
            patch.object(
                url_cache,
                "save_cached_url_analysis",
                side_effect=save_cached,
            ),
            patch.object(
                url_cache,
                "record_cached_url_scan",
                side_effect=record_scan,
            ),
            patch("app.main.analyze_url", side_effect=make_url_result) as analyzer,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            parent = main.analyze_qr(
                QRAnalyzeRequest(content=f"안내: {url}")
            )
            first_direct = main.analyze_qr(QRAnalyzeRequest(content=url))
            second_direct = main.analyze_qr(QRAnalyzeRequest(content=url))

        self.assertEqual(parent["qr_type"], "text_with_url")
        self.assertEqual(first_direct["history_event_type"], "initial_analysis")
        self.assertFalse(second_direct["history_saved"])
        self.assertEqual(second_direct["history_skip_reason"], "duplicate_unchanged")
        self.assertEqual(analyzer.call_count, 1)
        self.assertEqual(state["item"]["scan_count"], 2)
        self.assertEqual(db_mock.call_count, 2)
        self.assertEqual(db_mock.call_args_list[0].args[0]["qr_type"], "text_with_url")
        self.assertEqual(
            db_mock.call_args_list[1].args[0]["history_event_type"],
            "initial_analysis",
        )
        QRAnalyzeResponse.model_validate(parent)

    def test_scheme_less_candidate_keeps_non_url_analysis(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content="example.com"))

        cache_mock.assert_not_called()
        self.assertEqual(result["qr_type"], "text")

    def test_malformed_ipv6_is_client_error_without_internal_detail(self):
        with self.assertRaises(HTTPException) as raised:
            main.analyze_qr(QRAnalyzeRequest(content="http://[::1"))

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "유효하지 않은 HTTP(S) URL입니다.")
        self.assertNotIn("Invalid IPv6", raised.exception.detail)

    def test_decode_failure_is_client_error(self):
        with patch("app.main.decode_repeatedly", side_effect=ValueError("internal")):
            with self.assertRaises(HTTPException) as raised:
                main.analyze_qr(QRAnalyzeRequest(content="some-content"))

        self.assertEqual(raised.exception.status_code, 400)
        self.assertNotIn("internal", raised.exception.detail)

    def test_scan_endpoint_still_analyzes_and_saves(self):
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()) as db_mock,
        ):
            result = main.scan_url(ScanRequest(url="https://example.com"))

        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], "https://example.com")
        db_mock.assert_called_once()
        self.assertTrue(result["db_saved"])
        ScanResponse.model_validate(result)

    def test_initial_url_analysis_saves_initial_history_event(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "_history_should_save": True,
                "_history_event_type": "initial_analysis",
            }
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )

        history_payload = db_mock.call_args.args[0]
        self.assertEqual(history_payload["history_event_type"], "initial_analysis")
        self.assertNotIn("_history_should_save", result)
        self.assertNotIn("_history_event_type", result)
        self.assertTrue(result["db_saved"])
        self.assertTrue(result["history_saved"])
        self.assertEqual(result["history_event_type"], "initial_analysis")
        self.assertIsNone(result["history_skip_reason"])
        response_data = QRAnalyzeResponse.model_validate(result).model_dump()
        self.assertTrue(response_data["history_saved"])
        self.assertEqual(
            response_data["history_event_type"],
            "initial_analysis",
        )

    def test_fresh_url_cache_hit_skips_scan_history(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "cache_hit": True,
                "_history_should_save": False,
                "_history_event_type": None,
            }
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch("app.main.save_scan_result") as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )

        db_mock.assert_not_called()
        self.assertFalse(result["db_saved"])
        self.assertIsNone(result["db_error"])
        self.assertIsNone(result["scan_id"])
        self.assertFalse(result["history_saved"])
        self.assertIsNone(result["history_event_type"])
        self.assertEqual(
            result["history_skip_reason"],
            "duplicate_unchanged",
        )

    def test_scan_endpoint_uses_same_history_suppression(self):
        analysis_result = make_url_result("https://example.com/")
        analysis_result.update(
            {
                "cache_hit": True,
                "_history_should_save": False,
                "_history_event_type": None,
            }
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch("app.main.save_scan_result") as db_mock,
        ):
            result = main.scan_url(ScanRequest(url="https://example.com"))

        db_mock.assert_not_called()
        self.assertTrue(result["cache_hit"])
        self.assertFalse(result["db_saved"])
        response_data = ScanResponse.model_validate(result).model_dump()
        self.assertFalse(response_data["history_saved"])
        self.assertIsNone(response_data["history_event_type"])
        self.assertEqual(
            response_data["history_skip_reason"],
            "duplicate_unchanged",
        )

    def test_cache_fallback_exposes_saved_history_event(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "_history_should_save": True,
                "_history_event_type": "cache_fallback",
            }
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ),
        ):
            result = main.scan_url(ScanRequest(url="https://example.com"))

        self.assertTrue(result["db_saved"])
        self.assertTrue(result["history_saved"])
        self.assertEqual(result["history_event_type"], "cache_fallback")
        self.assertIsNone(result["history_skip_reason"])

    def test_risk_change_exposes_saved_history_event(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "_history_should_save": True,
                "_history_event_type": "risk_changed",
            }
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )

        self.assertTrue(result["history_saved"])
        self.assertEqual(result["history_event_type"], "risk_changed")
        self.assertIsNone(result["history_skip_reason"])

    def test_same_url_three_times_creates_one_history_and_three_scans(self):
        state = {"item": None}

        def get_cached(_url):
            return dict(state["item"]) if state["item"] else None

        def save_cached(url, result, **kwargs):
            self.assertTrue(kwargs["increment_scan"])
            now = kwargs["now_epoch"]
            state["item"] = make_cache_item(url, checked_at=now)
            state["item"].update(
                {
                    "scan_count": 1,
                    "first_seen_at": now,
                    "last_scanned_at": now,
                }
            )

        def record_scan(_url_hash, *, scanned_at):
            state["item"]["scan_count"] += 1
            state["item"]["last_scanned_at"] = scanned_at

        with (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                side_effect=get_cached,
            ),
            patch.object(
                url_cache,
                "save_cached_url_analysis",
                side_effect=save_cached,
            ),
            patch.object(
                url_cache,
                "record_cached_url_scan",
                side_effect=record_scan,
            ),
            patch("app.main.analyze_url", side_effect=make_url_result) as analyzer,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )
            main.scan_url(ScanRequest(url="https://example.com"))
            main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )

        analyzer.assert_called_once()
        self.assertEqual(state["item"]["scan_count"], 3)
        self.assertEqual(db_mock.call_count, 1)
        self.assertEqual(
            db_mock.call_args.args[0]["history_event_type"],
            "initial_analysis",
        )

    def test_db_failure_does_not_remove_analysis_result(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "_history_should_save": True,
                "_history_event_type": "initial_analysis",
            }
        )
        failed_db_result = {
            "saved": False,
            "scan_id": "test-scan-id",
            "created_at": "2026-01-01T00:00:00+00:00",
            "date": "2026-01-01",
            "error": "test failure",
        }
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch("app.main.save_scan_result", return_value=failed_db_result),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content="https://example.com"))

        self.assertFalse(result["db_saved"])
        self.assertEqual(result["db_error"], database.DATABASE_ERROR)
        self.assertNotIn("test failure", result["db_error"])
        self.assertFalse(result["history_saved"])
        self.assertEqual(result["history_event_type"], "initial_analysis")
        self.assertIsNone(result["history_skip_reason"])
        self.assertEqual(result["risk_score"], result["final_score"])

    def test_dynamodb_exception_is_not_exposed_by_api(self):
        internal_error = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": (
                        "User arn:aws:sts::123456789012:assumed-role/internal-role "
                        "cannot access arn:aws:dynamodb:ap-northeast-2:123456789012:"
                        "table/internal-table"
                    ),
                }
            },
            "PutItem",
        )

        class FailingTable:
            def put_item(self, **_kwargs):
                raise internal_error

        with (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch("app.services.database._get_table", return_value=FailingTable()),
            patch("app.services.database.logger.exception") as log_mock,
        ):
            db_result = database.save_scan_result(
                make_url_result("https://example.com")
            )

        log_mock.assert_called_once()
        api_result = main.attach_db_result(
            make_url_result("https://example.com"),
            db_result,
        )
        self.assertFalse(api_result["db_saved"])
        self.assertEqual(api_result["db_error"], database.DATABASE_ERROR)
        self.assertNotIn("123456789012", api_result["db_error"])
        self.assertNotIn("arn:aws", api_result["db_error"])
        self.assertNotIn("internal-table", api_result["db_error"])

    def test_non_url_history_metadata_is_not_applicable(self):
        with patch(
            "app.main.save_scan_result",
            return_value=make_db_result(),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content="안녕하세요"))

        self.assertTrue(result["db_saved"])
        self.assertIsNone(result["history_saved"])
        self.assertIsNone(result["history_event_type"])
        self.assertIsNone(result["history_skip_reason"])

    def test_dynamodb_payload_preserves_common_metadata_without_url_list(self):
        class CapturingTable:
            def __init__(self):
                self.item = None

            def put_item(self, *, Item):
                self.item = Item

        for analysis_result in (
            make_url_result("https://example.com"),
            main.ensure_analysis_contract(analyze_non_url_qr("안녕하세요")),
        ):
            with self.subTest(qr_type=analysis_result["qr_type"]):
                table = CapturingTable()
                with (
                    patch.object(database, "DYNAMODB_ENABLED", True),
                    patch("app.services.database._get_table", return_value=table),
                ):
                    db_result = database.save_scan_result(analysis_result)

                self.assertTrue(db_result["saved"])
                self.assertEqual(table.item["qr_type"], analysis_result["qr_type"])
                self.assertEqual(
                    table.item["contains_url"],
                    analysis_result["contains_url"],
                )
                self.assertEqual(
                    table.item["ruleset_version"],
                    analysis_result["ruleset_version"],
                )
                self.assertFalse(table.item["cache_hit"])
                self.assertFalse(table.item["cache_revalidated"])
                self.assertNotIn("extracted_urls", table.item)
                self.assertEqual(
                    table.item["url_count"],
                    len(analysis_result["extracted_urls"]),
                )

    def test_dynamodb_float_conversion_is_recursive(self):
        converted = database._to_dynamodb_safe(
            {"total_ms": 12.5, "nested": [1, {"vt_ms": 3.25}]}
        )

        self.assertEqual(converted["total_ms"], Decimal("12.5"))
        self.assertEqual(converted["nested"][0], 1)
        self.assertEqual(converted["nested"][1]["vt_ms"], Decimal("3.25"))

    def test_dynamodb_payload_preserves_history_event_type(self):
        class CapturingTable:
            item = None

            def put_item(self, *, Item):
                self.item = Item

        result = make_url_result("https://example.com")
        result["history_event_type"] = "risk_changed"
        table = CapturingTable()
        with (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch("app.services.database._get_table", return_value=table),
        ):
            database.save_scan_result(result)

        self.assertEqual(table.item["history_event_type"], "risk_changed")

    def test_text_with_url_db_stores_summary_without_embedded_results(self):
        class CapturingTable:
            item = None

            def put_item(self, *, Item):
                self.item = Item

        result = make_text_with_url_result(["https://example.com"], 20)
        result.update(
            {
                "text_score": 20,
                "embedded_url_count": 1,
                "analyzed_embedded_url_count": 1,
                "embedded_url_max_score": 55,
                "embedded_url_results": [
                    make_scored_url_result("https://example.com", 55)
                ],
                "local_score": 20,
                "vt_score_delta": 0,
                "final_score": 55,
                "risk_score": 55,
                "ruleset_version": "1.0",
            }
        )
        table = CapturingTable()
        with (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch("app.services.database._get_table", return_value=table),
        ):
            database.save_scan_result(result)

        self.assertEqual(table.item["text_score"], 20)
        self.assertEqual(table.item["embedded_url_count"], 1)
        self.assertEqual(table.item["analyzed_embedded_url_count"], 1)
        self.assertEqual(table.item["embedded_url_max_score"], 55)
        self.assertNotIn("embedded_url_results", table.item)
        self.assertNotIn("extracted_urls", table.item)

    def test_dashboard_preserves_new_metadata(self):
        item = {
            "scan_id": "test-id",
            "qr_type": "text",
            "contains_url": False,
            "url_count": 0,
            "local_score": 0,
            "vt_score_delta": 0,
            "final_score": 0,
            "risk_score": 0,
            "ruleset_version": "1.0",
            "analysis_flags": {},
        }

        dashboard_item = database._make_dashboard_item(item)
        self.assertEqual(dashboard_item["qr_type"], "text")
        self.assertFalse(dashboard_item["contains_url"])
        self.assertEqual(dashboard_item["final_score"], 0)
        self.assertEqual(dashboard_item["ruleset_version"], "1.0")
        self.assertFalse(dashboard_item["cache_hit"])
        self.assertFalse(dashboard_item["cache_revalidated"])

    def test_summary_scan_limit_accepts_requested_200_items(self):
        class EmptyTable:
            def __init__(self):
                self.scan_kwargs = None

            def scan(self, **kwargs):
                self.scan_kwargs = kwargs
                return {"Items": []}

        table = EmptyTable()
        with (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch("app.services.database._get_table", return_value=table),
        ):
            database.list_scan_results(limit=200)

        self.assertEqual(table.scan_kwargs["Limit"], 200)

    def test_mangum_handler_remains_configured(self):
        self.assertIsNotNone(main.handler)


class AdminEndpointSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.admin_key = "unit-test-admin-key"

    def test_scans_accepts_correct_admin_key(self):
        with (
            patch.object(main, "ADMIN_API_KEY", self.admin_key),
            patch("app.main.list_scan_results", return_value=[]) as list_mock,
        ):
            response = self.client.get(
                "/scans",
                headers={"X-Admin-Key": self.admin_key},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"items": []})
        list_mock.assert_called_once()

    def test_scans_rejects_missing_or_wrong_admin_key(self):
        with patch.object(main, "ADMIN_API_KEY", self.admin_key):
            missing = self.client.get("/scans")
            wrong = self.client.get(
                "/scans",
                headers={"X-Admin-Key": "wrong-test-key"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)

    def test_summary_requires_admin_key(self):
        with (
            patch.object(main, "ADMIN_API_KEY", self.admin_key),
            patch(
                "app.main.get_scan_summary",
                return_value={"total": 0},
            ) as summary_mock,
        ):
            allowed = self.client.get(
                "/scans/summary",
                headers={"X-Admin-Key": self.admin_key},
            )
            missing = self.client.get("/scans/summary")
            wrong = self.client.get(
                "/scans/summary",
                headers={"X-Admin-Key": "wrong-test-key"},
            )

        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.json(), {"total": 0})
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        summary_mock.assert_called_once()

    def test_admin_endpoints_fail_closed_without_server_key(self):
        with patch.object(main, "ADMIN_API_KEY", ""):
            response = self.client.get(
                "/scans",
                headers={"X-Admin-Key": "any-test-key"},
            )

        self.assertEqual(response.status_code, 503)

    def test_analysis_endpoints_do_not_require_admin_key(self):
        analysis_result = make_url_result("https://example.com")
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=analysis_result,
            ),
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            scan_response = self.client.post(
                "/scan",
                json={"url": "https://example.com"},
            )
            analyze_response = self.client.post(
                "/analyze-qr",
                json={"content": "https://example.com"},
            )

        self.assertEqual(scan_response.status_code, 200)
        self.assertEqual(analyze_response.status_code, 200)


class UrlCacheTests(unittest.TestCase):
    def setUp(self):
        self.real_record_cached_url_scan = url_cache.record_cached_url_scan
        patches = (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(url_cache, "URL_CACHE_FRESHNESS_SECONDS", 100),
            patch.object(url_cache.virustotal, "VIRUSTOTAL_ENABLED", True),
            patch.object(url_cache.virustotal, "VIRUSTOTAL_API_KEY", "test-key"),
            patch.object(url_cache, "record_cached_url_scan"),
        )
        for index, active_patch in enumerate(patches):
            started = active_patch.start()
            if index == len(patches) - 1:
                self.scan_record_mock = started
            self.addCleanup(active_patch.stop)

    def test_cache_disabled_preserves_analyzer_result(self):
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with patch.object(url_cache, "URL_CACHE_ENABLED", False):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once_with("https://example.com")
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["status"], "safe")
        self.assertFalse(result["cache_hit"])
        self.assertIsNone(result["revalidation_reason"])
        self.assertTrue(result["_history_should_save"])

    def test_initial_cache_write_sets_scan_metadata_atomically(self):
        class CacheTable:
            update = None

            def update_item(self, **kwargs):
                self.update = kwargs

        table = CacheTable()
        with patch.object(url_cache, "_get_cache_table", return_value=table):
            url_cache.save_cached_url_analysis(
                "https://example.com",
                make_url_result("https://example.com"),
                now_epoch=1000,
                increment_scan=True,
            )

        expression = table.update["UpdateExpression"]
        values = table.update["ExpressionAttributeValues"]
        self.assertIn("if_not_exists(#first_seen_at, :scan_time)", expression)
        self.assertIn("#last_scanned_at = :scan_time", expression)
        self.assertIn("ADD #scan_count :one", expression)
        self.assertEqual(values[":scan_time"], 1000)
        self.assertEqual(values[":one"], 1)
        self.assertNotIn("https://example.com", repr(table.update))

    def test_existing_cache_scan_update_supports_legacy_item(self):
        class CacheTable:
            update = None

            def update_item(self, **kwargs):
                self.update = kwargs

        table = CacheTable()
        with patch.object(url_cache, "_get_cache_table", return_value=table):
            self.real_record_cached_url_scan(
                url_cache.build_url_hash("https://example.com"),
                scanned_at=1100,
            )

        expression = table.update["UpdateExpression"]
        self.assertIn("if_not_exists(#first_seen_at, :scanned_at)", expression)
        self.assertIn("ADD #scan_count :one", expression)
        self.assertIn(
            "#direct_history_initialized = :direct_history_initialized",
            expression,
        )
        self.assertEqual(
            table.update["ExpressionAttributeValues"],
            {
                ":scanned_at": 1100,
                ":direct_history_initialized": True,
                ":one": 1,
            },
        )

    def test_cache_miss_analyzes_and_saves(self):
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=None),
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once()
        self.scan_record_mock.assert_not_called()
        save_mock.assert_called_once()
        self.assertTrue(save_mock.call_args.kwargs["increment_scan"])
        self.assertTrue(
            save_mock.call_args.kwargs["direct_history_initialized"]
        )
        self.assertFalse(result["cache_hit"])
        self.assertEqual(result["revalidation_reason"], "cache_miss")
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "initial_analysis")

    def test_embedded_cache_miss_does_not_record_direct_scan_or_history(self):
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=None),
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
                analysis_context="embedded",
            )

        analyzer.assert_called_once_with("https://example.com")
        self.scan_record_mock.assert_not_called()
        save_mock.assert_called_once()
        self.assertFalse(save_mock.call_args.kwargs["increment_scan"])
        self.assertFalse(
            save_mock.call_args.kwargs["direct_history_initialized"]
        )
        self.assertNotIn("_history_should_save", result)
        self.assertNotIn("_history_event_type", result)

    def test_fresh_embedded_cache_hit_skips_analyzer_vt_and_scan_counter(self):
        cached = make_cache_item(
            "https://example.com",
            checked_at=950,
            direct_history_initialized=False,
        )
        analyzer = Mock()
        with patch.object(
            url_cache,
            "get_cached_url_analysis",
            return_value=cached,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
                analysis_context="embedded",
            )

        analyzer.assert_not_called()
        self.scan_record_mock.assert_not_called()
        self.assertTrue(result["cache_hit"])
        self.assertEqual(result["cache_age_seconds"], 50)
        self.assertNotIn("_history_should_save", result)

    def test_direct_scan_of_embedded_created_cache_requests_initial_history(self):
        cached = make_cache_item(
            "https://example.com",
            checked_at=950,
            direct_history_initialized=False,
        )
        with patch.object(
            url_cache,
            "get_cached_url_analysis",
            return_value=cached,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(),
                now_epoch=1000,
            )

        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        self.assertTrue(result["cache_hit"])
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "initial_analysis")

    def test_stale_embedded_cache_revalidates_without_direct_history(self):
        current = make_vt_url_result("https://example.com")
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            direct_history_initialized=False,
            **{
                key: value
                for key, value in current.items()
                if key in url_cache._CACHE_RESULT_FIELDS
            },
        )
        analyzer = Mock(return_value=current)
        with (
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                return_value=cached,
            ),
            patch.object(url_cache, "update_cache_check_time") as update_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
                analysis_context="embedded",
            )

        analyzer.assert_called_once()
        self.scan_record_mock.assert_not_called()
        update_mock.assert_called_once()
        self.assertTrue(result["cache_revalidated"])
        self.assertNotIn("_history_should_save", result)

    def test_fresh_cache_hit_skips_analyzer(self):
        cached = make_cache_item("https://example.com", checked_at=950)
        analyzer = Mock()
        with patch.object(url_cache, "get_cached_url_analysis", return_value=cached):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_not_called()
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        self.assertTrue(result["cache_hit"])
        self.assertEqual(result["cache_age_seconds"], 50)
        self.assertEqual(result["extracted_urls"], ["https://example.com"])

    def test_ruleset_mismatch_reanalyzes_and_replaces_cache(self):
        cached = make_cache_item(
            "https://example.com",
            checked_at=990,
            ruleset_version="0.9",
        )
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=cached),
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once()
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        save_mock.assert_called_once()
        self.assertTrue(result["cache_revalidated"])
        self.assertEqual(result["revalidation_reason"], "ruleset_changed")
        self.assertFalse(result["_history_should_save"])

    def test_stale_cache_revalidates_and_updates_check_time_when_unchanged(self):
        current = make_vt_url_result("https://example.com")
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            **{key: value for key, value in current.items() if key in url_cache._CACHE_RESULT_FIELDS},
        )
        analyzer = Mock(return_value=current)
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=cached),
            patch.object(url_cache, "update_cache_check_time") as update_mock,
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once()
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        update_mock.assert_called_once_with(
            cached["url_hash"],
            checked_at=1000,
            vt_checked_at=1000,
        )
        save_mock.assert_not_called()
        self.assertTrue(result["cache_revalidated"])
        self.assertEqual(result["revalidation_reason"], "stale_cache")
        self.assertFalse(result["_history_should_save"])

    def test_safe_to_danger_records_previous_risk(self):
        cached_result = make_vt_url_result("https://example.com", harmless=5)
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            **{key: value for key, value in cached_result.items() if key in url_cache._CACHE_RESULT_FIELDS},
        )
        danger = make_vt_url_result("https://example.com", malicious=3, harmless=0)

        class CacheTable:
            update = None

            def get_item(self, **_):
                return {"Item": cached}

            def update_item(self, **kwargs):
                self.update = kwargs

        table = CacheTable()
        with patch.object(url_cache, "_get_cache_table", return_value=table):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(return_value=danger),
                now_epoch=1000,
            )

        self.assertEqual(result["status"], "danger")
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        values = table.update["ExpressionAttributeValues"]
        self.assertEqual(values[":previous_status"], "safe")
        self.assertEqual(values[":previous_score"], 10)
        self.assertEqual(values[":changed_at"], 1000)
        self.assertNotIn("https://example.com", repr(table.update))
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "risk_changed")

    def test_vt_metadata_change_updates_without_status_change_marker(self):
        old_result = make_vt_url_result("https://example.com", harmless=1)
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            **{key: value for key, value in old_result.items() if key in url_cache._CACHE_RESULT_FIELDS},
        )
        current = make_vt_url_result("https://example.com", harmless=2)

        class CacheTable:
            update = None

            def get_item(self, **_):
                return {"Item": cached}

            def update_item(self, **kwargs):
                self.update = kwargs

        table = CacheTable()
        with patch.object(url_cache, "_get_cache_table", return_value=table):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(return_value=current),
                now_epoch=1000,
            )

        self.assertEqual(result["status"], "safe")
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        values = table.update["ExpressionAttributeValues"]
        self.assertEqual(values[":vt_harmless"], 2)
        self.assertNotIn(":previous_status", values)
        self.assertNotIn(":changed_at", values)
        self.assertFalse(result["_history_should_save"])

    def test_cache_get_failure_falls_back_to_analysis(self):
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache, "get_cached_url_analysis", side_effect=RuntimeError("denied")),
            patch.object(url_cache, "save_cached_url_analysis"),
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once()
        self.assertEqual(result["risk_score"], 10)
        self.assertIsNone(result["revalidation_reason"])
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "cache_fallback")

    def test_cache_write_failure_does_not_fail_analysis(self):
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=None),
            patch.object(
                url_cache,
                "save_cached_url_analysis",
                side_effect=RuntimeError("missing table"),
            ),
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(return_value=make_url_result("https://example.com")),
                now_epoch=1000,
            )

        self.assertEqual(result["status"], "safe")

    def test_cache_update_failure_does_not_fail_analysis(self):
        current = make_vt_url_result("https://example.com")
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            **{key: value for key, value in current.items() if key in url_cache._CACHE_RESULT_FIELDS},
        )
        with (
            patch.object(url_cache, "get_cached_url_analysis", return_value=cached),
            patch.object(
                url_cache,
                "update_cache_check_time",
                side_effect=RuntimeError("denied"),
            ),
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(return_value=current),
                now_epoch=1000,
            )

        self.assertTrue(result["cache_revalidated"])
        self.assertEqual(result["status"], "safe")

    def test_scan_counter_update_failure_requests_history_fallback(self):
        cached = make_cache_item("https://example.com", checked_at=950)
        with (
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                return_value=cached,
            ),
            patch.object(
                url_cache,
                "record_cached_url_scan",
                side_effect=RuntimeError("denied"),
            ),
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(),
                now_epoch=1000,
            )

        self.assertTrue(result["cache_hit"])
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "cache_fallback")

    def test_stale_cache_with_vt_disabled_preserves_cached_danger(self):
        cached_result = make_vt_url_result("https://example.com", malicious=3)
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            **{key: value for key, value in cached_result.items() if key in url_cache._CACHE_RESULT_FIELDS},
        )
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache.virustotal, "VIRUSTOTAL_ENABLED", False),
            patch.object(url_cache, "get_cached_url_analysis", return_value=cached),
            patch.object(url_cache, "_record_deferred_revalidation") as deferred_mock,
            patch.object(url_cache, "update_cache_check_time") as checked_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_not_called()
        deferred_mock.assert_called_once()
        checked_mock.assert_not_called()
        self.scan_record_mock.assert_called_once_with(
            cached["url_hash"],
            scanned_at=1000,
        )
        self.assertFalse(result["cache_hit"])
        self.assertFalse(result["cache_revalidated"])
        self.assertEqual(result["status"], "danger")
        self.assertEqual(result["final_score"], 80)
        self.assertFalse(result["_history_should_save"])

    def test_ruleset_change_with_risk_change_requests_history(self):
        cached = make_cache_item(
            "https://example.com",
            checked_at=990,
            ruleset_version="0.9",
        )
        danger = make_vt_url_result(
            "https://example.com",
            malicious=3,
            harmless=0,
        )
        with (
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                return_value=cached,
            ),
            patch.object(url_cache, "save_cached_url_analysis"),
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=Mock(return_value=danger),
                now_epoch=1000,
            )

        self.assertTrue(result["cache_revalidated"])
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(result["_history_event_type"], "risk_changed")

    def test_ruleset_change_with_vt_disabled_keeps_historical_vt_risk(self):
        cached_result = make_vt_url_result("https://example.com", malicious=3)
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            ruleset_version="0.9",
            **{
                key: value
                for key, value in cached_result.items()
                if key in url_cache._CACHE_RESULT_FIELDS and key != "ruleset_version"
            },
        )
        analyzer = Mock(return_value=make_url_result("https://example.com"))
        with (
            patch.object(url_cache.virustotal, "VIRUSTOTAL_ENABLED", False),
            patch.object(url_cache, "get_cached_url_analysis", return_value=cached),
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                "https://example.com",
                analyzer=analyzer,
                now_epoch=1000,
            )

        analyzer.assert_called_once()
        self.assertEqual(result["ruleset_version"], "1.0")
        self.assertEqual(result["status"], "danger")
        self.assertEqual(result["final_score"], 80)
        self.assertFalse(result["cache_revalidated"])
        self.assertEqual(save_mock.call_args.kwargs["last_checked_at"], 800)
        self.assertFalse(result["_history_should_save"])


if __name__ == "__main__":
    unittest.main()
