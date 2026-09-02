import unittest
from decimal import Decimal
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main
from app.constants import RULESET_VERSION
from app.schemas import QRAnalyzeRequest, QRAnalyzeResponse, ScanRequest, ScanResponse
from app.services import database, qr_analyzer, url_cache
from app.services.qr_analyzer import analyze_non_url_qr
from app.services.scanner import analyze_url, analyze_url_with_vt_result


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
        "ruleset_version": RULESET_VERSION,
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


def make_structured_parent_result(
    qr_type: str,
    urls: list[str],
    score: int,
) -> dict:
    status = "danger" if score >= 70 else "warning" if score >= 30 else "safe"
    return {
        "qr_type": qr_type,
        "raw_content_preview": f"{qr_type} preview",
        "contains_url": bool(urls),
        "extracted_urls": list(urls),
        "contains_url_candidate": False,
        "extracted_url_candidates": [],
        "candidate_url_count": 0,
        "structured_content": {},
        "social_engineering_categories": [],
        "social_engineering_category_count": 0,
        "url": urls[0] if urls else None,
        "domain": "example.com" if urls else None,
        "risk_score": score,
        "status": status,
        "message": f"{qr_type} score {score}",
        "reasons": [
            "일반 텍스트 안에 URL이 포함되어 있습니다. 포함된 URL 분석이 필요합니다."
        ] if urls else [f"{qr_type} content"],
        "analysis_flags": {"contains_url": bool(urls)},
        "raw_result": {"qr_type": qr_type},
        "_embedded_body_urls": list(urls),
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
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)

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

    def test_normal_url_has_no_new_structural_signals(self):
        result = analyze_url_with_vt_result(
            "https://example.com",
            {"enabled": False, "available": False},
        )

        flags = result["analysis_flags"]
        self.assertEqual(result["local_score"], 10)
        self.assertFalse(flags["punycode_hostname"])
        self.assertFalse(flags["nonstandard_port"])
        self.assertFalse(flags["excessive_hostname_labels"])
        self.assertEqual(flags["hostname_label_count"], 2)
        self.assertIsNone(flags["explicit_port"])

    def test_punycode_hostname_adds_fifteen_points(self):
        result = analyze_url_with_vt_result(
            "https://xn--example-xxxx.com",
            {"enabled": False, "available": False},
        )

        self.assertEqual(result["local_score"], 25)
        self.assertTrue(result["analysis_flags"]["punycode_hostname"])
        self.assertIn(
            "국제화 도메인(Punycode) 형식이 사용되었습니다.",
            result["reasons"],
        )

    def test_punycode_is_detected_in_any_hostname_label(self):
        result = analyze_url_with_vt_result(
            "https://login.xn--example-xxxx.com",
            {"enabled": False, "available": False},
        )

        self.assertTrue(result["analysis_flags"]["punycode_hostname"])
        self.assertEqual(result["local_score"], 35)

    def test_standard_explicit_ports_do_not_add_points(self):
        for url, expected_score, expected_port in (
            ("https://example.com:443", 10, 443),
            ("http://example.com:80", 30, 80),
        ):
            with self.subTest(url=url):
                result = analyze_url_with_vt_result(
                    url,
                    {"enabled": False, "available": False},
                )
                self.assertEqual(result["local_score"], expected_score)
                self.assertFalse(result["analysis_flags"]["nonstandard_port"])
                self.assertEqual(
                    result["analysis_flags"]["explicit_port"],
                    expected_port,
                )

    def test_nonstandard_ports_add_ten_points(self):
        for url, expected_score, expected_port in (
            ("https://example.com:8443", 20, 8443),
            ("http://example.com:8080", 40, 8080),
        ):
            with self.subTest(url=url):
                result = analyze_url_with_vt_result(
                    url,
                    {"enabled": False, "available": False},
                )
                self.assertEqual(result["local_score"], expected_score)
                self.assertTrue(result["analysis_flags"]["nonstandard_port"])
                self.assertEqual(
                    result["analysis_flags"]["explicit_port"],
                    expected_port,
                )

    def test_hostname_label_threshold_is_five(self):
        excessive = analyze_url_with_vt_result(
            "https://secure.login.account.example.com",
            {"enabled": False, "available": False},
        )
        below_threshold = analyze_url_with_vt_result(
            "https://login.account.example.com",
            {"enabled": False, "available": False},
        )

        self.assertEqual(excessive["analysis_flags"]["hostname_label_count"], 5)
        self.assertTrue(
            excessive["analysis_flags"]["excessive_hostname_labels"]
        )
        self.assertEqual(excessive["local_score"], 50)
        self.assertEqual(
            below_threshold["analysis_flags"]["hostname_label_count"],
            4,
        )
        self.assertFalse(
            below_threshold["analysis_flags"]["excessive_hostname_labels"]
        )
        self.assertEqual(below_threshold["local_score"], 30)

    def test_label_and_port_signals_are_independently_added(self):
        result = analyze_url_with_vt_result(
            "https://a.b.c.example.com:8443",
            {"enabled": False, "available": False},
        )

        self.assertEqual(result["local_score"], 30)
        self.assertTrue(result["analysis_flags"]["nonstandard_port"])
        self.assertTrue(
            result["analysis_flags"]["excessive_hostname_labels"]
        )

    def test_punycode_and_port_signals_are_independently_added(self):
        result = analyze_url_with_vt_result(
            "https://xn--example-xxxx.com:8443",
            {"enabled": False, "available": False},
        )

        self.assertEqual(result["local_score"], 35)
        self.assertTrue(result["analysis_flags"]["punycode_hostname"])
        self.assertTrue(result["analysis_flags"]["nonstandard_port"])

    def test_ip_host_does_not_receive_hostname_label_score(self):
        result = analyze_url_with_vt_result(
            "https://192.168.0.1",
            {"enabled": False, "available": False},
        )

        self.assertEqual(result["local_score"], 85)
        self.assertTrue(result["analysis_flags"]["ip_address_host"])
        self.assertFalse(
            result["analysis_flags"]["excessive_hostname_labels"]
        )
        self.assertEqual(result["analysis_flags"]["hostname_label_count"], 0)

    def test_trailing_dot_does_not_increase_hostname_label_count(self):
        result = analyze_url_with_vt_result(
            "https://example.com.",
            {"enabled": False, "available": False},
        )

        self.assertEqual(result["local_score"], 10)
        self.assertEqual(result["analysis_flags"]["hostname_label_count"], 2)
        self.assertFalse(
            result["analysis_flags"]["excessive_hostname_labels"]
        )

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
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)

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
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["text_score"], 0)
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

    def test_scheme_less_candidate_is_reported_without_url_analysis(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
            patch.object(
                qr_analyzer,
                "extract_url_candidates",
                wraps=qr_analyzer.extract_url_candidates,
            ) as candidate_extractor,
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content="example.com"))

        cache_mock.assert_not_called()
        candidate_extractor.assert_called_once()
        self.assertEqual(result["qr_type"], "text_with_url")
        self.assertFalse(result["contains_url"])
        self.assertTrue(result["contains_url_candidate"])
        self.assertEqual(result["extracted_url_candidates"], ["example.com"])
        self.assertEqual(result["candidate_url_count"], 1)
        self.assertEqual(result["text_score"], 0)
        self.assertEqual(result["embedded_url_results"], [])
        QRAnalyzeResponse.model_validate(result)

    def test_scheme_less_candidate_preserves_path_and_original_case(self):
        for content, expected in (
            ("www.example.com/login", "www.example.com/login"),
            ("WWW.Example.COM/Login", "WWW.Example.COM/Login"),
            ("sub.example.com/path?q=test", "sub.example.com/path?q=test"),
        ):
            with self.subTest(content=content):
                result = analyze_non_url_qr(content)
                self.assertEqual(result["extracted_url_candidates"], [expected])

    def test_candidate_is_extracted_from_korean_text(self):
        result = analyze_non_url_qr(
            "로그인은 example.co.kr/account에서 하세요"
        )

        self.assertEqual(result["qr_type"], "text_with_url")
        self.assertEqual(
            result["extracted_url_candidates"],
            ["example.co.kr/account"],
        )

    def test_http_url_is_not_duplicated_as_candidate(self):
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="https://example.com")
            )

        cache_mock.assert_called_once()
        self.assertEqual(result["extracted_urls"], ["https://example.com"])
        self.assertFalse(result["contains_url_candidate"])
        self.assertEqual(result["extracted_url_candidates"], [])

    def test_http_url_and_candidate_are_separate_without_double_scoring(self):
        content = "https://example.com 그리고 example.org"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], "https://example.com")
        self.assertEqual(result["extracted_urls"], ["https://example.com"])
        self.assertEqual(result["extracted_url_candidates"], ["example.org"])
        self.assertEqual(result["text_score"], 0)

    def test_email_file_and_ipv4_are_not_candidates(self):
        for content, expected_type in (
            ("user@example.com", "email_text"),
            ("document.pdf", "text"),
            ("image.png", "text"),
            ("192.168.0.1", "text"),
        ):
            with self.subTest(content=content):
                result = analyze_non_url_qr(content)
                self.assertEqual(result["qr_type"], expected_type)
                self.assertFalse(result["contains_url_candidate"])
                self.assertEqual(result["extracted_url_candidates"], [])

    def test_candidate_deduplication_is_case_insensitive_and_preserves_first(self):
        result = analyze_non_url_qr(
            "Example.com example.com EXAMPLE.COM"
        )

        self.assertEqual(result["extracted_url_candidates"], ["Example.com"])
        self.assertEqual(result["candidate_url_count"], 1)

    def test_candidate_response_list_is_limited_to_ten(self):
        content = " ".join(f"site{index}.example" for index in range(11))
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        cache_mock.assert_not_called()
        self.assertEqual(result["candidate_url_count"], 11)
        self.assertEqual(len(result["extracted_url_candidates"]), 10)

    def test_punycode_candidate_does_not_add_a_new_risk_rule(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="xn--example-xxxx.com")
            )

        cache_mock.assert_not_called()
        self.assertEqual(
            result["extracted_url_candidates"],
            ["xn--example-xxxx.com"],
        )
        self.assertEqual(result["risk_score"], 0)
        self.assertNotIn("punycode_hostname", result["analysis_flags"])

    def test_embedded_punycode_url_uses_same_url_analyzer_rules(self):
        with (
            patch(
                "app.services.scanner.get_url_report",
                return_value={"enabled": False, "available": False},
            ),
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(
                    content="안내: https://xn--example-xxxx.com"
                )
            )

        self.assertEqual(result["qr_type"], "text_with_url")
        self.assertEqual(result["embedded_url_max_score"], 25)
        self.assertEqual(result["final_score"], 25)
        self.assertTrue(
            result["embedded_url_results"][0]["analysis_flags"][
                "punycode_hostname"
            ]
        )

    def test_existing_non_url_types_remain_classified(self):
        for content, expected_type in (
            ("010-1234-5678", "phone_text"),
            ("user@example.com", "email_text"),
            ("SMS:01012345678:hello", "sms"),
            ("WIFI:T:WPA;S:test;P:password;;", "wifi"),
        ):
            with self.subTest(content=content):
                self.assertEqual(analyze_non_url_qr(content)["qr_type"], expected_type)

    def test_tel_qr_exposes_only_masked_phone_metadata(self):
        for content, expected_masked, expected_score in (
            ("tel:01012345678", "010****5678", 0),
            ("TEL:+821012345678", "+8210****5678", 0),
        ):
            with self.subTest(content=content):
                result = main.ensure_analysis_contract(
                    analyze_non_url_qr(content)
                )
                self.assertEqual(result["qr_type"], "phone")
                self.assertEqual(
                    result["structured_content"]["phone_number_masked"],
                    expected_masked,
                )
                self.assertEqual(result["risk_score"], expected_score)
                self.assertTrue(
                    result["analysis_flags"]["has_structured_phone"]
                )
                self.assertNotIn(content.split(":", 1)[1], repr(result))
                QRAnalyzeResponse.model_validate(result)

    def test_smsto_parses_masked_recipient_body_and_category(self):
        result = main.ensure_analysis_contract(
            analyze_non_url_qr(
                "SMSTO:01012345678:인증번호를 입력하세요"
            )
        )
        structured = result["structured_content"]

        self.assertEqual(result["qr_type"], "sms")
        self.assertEqual(structured["sms_recipient_masked"], "010****5678")
        self.assertEqual(structured["sms_body_preview"], "인증번호를 입력하세요")
        self.assertEqual(structured["sms_body_length"], 11)
        self.assertEqual(
            result["social_engineering_categories"],
            ["credential_request"],
        )
        self.assertEqual(result["risk_score"], 20)
        self.assertNotIn("01012345678", repr(result))

    def test_sms_uri_categories_use_bounded_v2_score(self):
        result = main.ensure_analysis_contract(
            analyze_non_url_qr(
                "sms:01012345678?body=긴급 로그인 확인"
            )
        )

        self.assertEqual(
            result["social_engineering_categories"],
            ["credential_request", "urgency"],
        )
        self.assertEqual(result["social_engineering_category_count"], 2)
        self.assertEqual(
            result["analysis_flags"]["social_engineering_category_count"],
            2,
        )
        self.assertEqual(result["risk_score"], 45)
        self.assertEqual(
            result["analysis_flags"]["combined_signal_rules"],
            ["URGENCY_WITH_CREDENTIAL_OR_PERSONAL_INFO"],
        )

    def test_social_engineering_categories_cover_each_supported_meaning(self):
        result = analyze_non_url_qr(
            "로그인 후 즉시 송금하세요. 보안팀 안내이며 당첨 상품 수령을 위해 개인정보를 확인합니다."
        )

        self.assertEqual(
            result["social_engineering_categories"],
            [
                "credential_request",
                "payment_request",
                "urgency",
                "impersonation_support",
                "prize_reward",
                "personal_info_request",
            ],
        )
        self.assertEqual(result["social_engineering_category_count"], 6)

    def test_scoring_v2_benign_structured_qrs_remain_safe(self):
        cases = (
            ("tel:+821012345678", "phone", 0),
            ("mailto:hello@example.com?subject=Hello", "email", 0),
            ("SMSTO:01012345678:오늘 7시에 만나자", "sms", 0),
            (
                "sms:01012345678?body=회의가%20늦게%20끝날%20것%20같아",
                "sms",
                0,
            ),
            ("WIFI:T:WPA;S:HomeWiFi;P:testpassword;;", "wifi", 0),
            (
                "mailto:hello@example.com?body=https%3A%2F%2Fexample.com",
                "email",
                10,
            ),
            (
                "sms:01012345678?body=https%3A%2F%2Fexample.com",
                "sms",
                10,
            ),
        )

        for content, qr_type, expected_score in cases:
            with self.subTest(content=content):
                with (
                    patch(
                        "app.main.analyze_url_with_cache",
                        side_effect=lambda url, **_: make_url_result(url),
                    ),
                    patch(
                        "app.main.save_scan_result",
                        return_value=make_db_result(),
                    ),
                ):
                    result = main.analyze_qr(QRAnalyzeRequest(content=content))

                self.assertEqual(result["qr_type"], qr_type)
                self.assertEqual(result["risk_score"], expected_score)
                self.assertEqual(result["status"], "safe")

    def test_scoring_v2_combined_social_signals_are_stronger(self):
        single_payment = analyze_non_url_qr("송금 요청입니다")
        combined = analyze_non_url_qr("긴급: 지금 송금하세요")

        self.assertEqual(single_payment["risk_score"], 25)
        self.assertEqual(combined["risk_score"], 55)
        self.assertGreater(
            combined["risk_score"],
            single_payment["risk_score"],
        )
        self.assertEqual(combined["status"], "warning")
        self.assertIn(
            "URGENCY_WITH_PAYMENT",
            combined["analysis_flags"]["combined_signal_rules"],
        )

    def test_scoring_v2_repeated_keywords_do_not_multiply_category_score(self):
        single = analyze_non_url_qr("로그인 요청")
        repeated = analyze_non_url_qr("로그인 로그인 비밀번호 보안코드")

        self.assertEqual(single["risk_score"], 20)
        self.assertEqual(repeated["risk_score"], 20)
        self.assertEqual(
            repeated["analysis_flags"]["score_components"][
                "social_engineering"
            ],
            20,
        )

    def test_scoring_v2_suspicious_sms_uses_social_and_url_evidence(self):
        url = "https://suspicious.example/account"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=make_scored_url_result(url, 80),
            ),
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(
                    content=(
                        "SMSTO:01012345678:계정이 정지됩니다. "
                        f"지금 본인인증하세요 {url}"
                    )
                )
            )

        self.assertEqual(result["qr_type"], "sms")
        self.assertEqual(result["text_score"], 55)
        self.assertEqual(result["embedded_url_max_score"], 80)
        self.assertEqual(result["final_score"], 80)
        self.assertEqual(result["status"], "danger")

    def test_scoring_v2_suspicious_mail_uses_embedded_url_score(self):
        url = "https://suspicious.example/login"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                return_value=make_scored_url_result(url, 55),
            ),
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(
                    content=f"mailto:user@example.com?body=로그인하세요%20{url}"
                )
            )

        self.assertEqual(result["qr_type"], "email")
        self.assertEqual(result["text_score"], 20)
        self.assertEqual(result["embedded_url_max_score"], 55)
        self.assertEqual(result["final_score"], 55)
        self.assertEqual(result["status"], "warning")

    def test_scoring_v2_long_content_is_only_a_combined_signal(self):
        benign_long = analyze_non_url_qr("일상적인 안내 " * 40)
        social_short = analyze_non_url_qr("긴급 로그인 확인")
        social_long = analyze_non_url_qr(
            "긴급 로그인 확인 " + ("추가 안내 " * 60)
        )

        self.assertTrue(benign_long["analysis_flags"]["long_content"])
        self.assertEqual(benign_long["risk_score"], 0)
        self.assertEqual(social_short["risk_score"], 45)
        self.assertEqual(social_long["risk_score"], 50)
        self.assertIn(
            "LONG_CONTENT_WITH_MULTI_SOCIAL",
            social_long["analysis_flags"]["combined_signal_rules"],
        )

    def test_scoring_v2_dangerous_scheme_remains_strong_evidence(self):
        result = analyze_non_url_qr("javascript:alert(1)")

        self.assertEqual(result["qr_type"], "dangerous_scheme")
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["status"], "danger")
        self.assertTrue(result["analysis_flags"]["dangerous_scheme"])
        self.assertEqual(
            result["analysis_flags"]["score_components"]["dangerous_scheme"],
            70,
        )

    def test_sms_body_preview_is_limited_to_one_hundred_characters(self):
        body = "가" * 150
        result = analyze_non_url_qr(f"sms:01012345678?body={body}")
        structured = result["structured_content"]

        self.assertEqual(structured["sms_body_length"], 150)
        self.assertLessEqual(len(structured["sms_body_preview"]), 100)

    def test_mailto_parses_domain_masked_address_and_subject(self):
        result = main.ensure_analysis_contract(
            analyze_non_url_qr(
                "mailto:user@example.com?subject=계정확인"
            )
        )
        structured = result["structured_content"]

        self.assertEqual(result["qr_type"], "email")
        self.assertEqual(structured["email_domain"], "example.com")
        self.assertEqual(structured["email_address_masked"], "u***@example.com")
        self.assertEqual(structured["email_subject_preview"], "계정확인")
        self.assertEqual(result["risk_score"], 20)
        self.assertIn(
            "credential_request",
            result["social_engineering_categories"],
        )
        self.assertNotIn("user@example.com", repr(result))

    def test_mail_body_category_does_not_add_duplicate_score(self):
        result = analyze_non_url_qr(
            "mailto:user@example.com?body=로그인해주세요"
        )

        self.assertEqual(result["structured_content"]["email_body_length"], 7)
        self.assertEqual(
            result["structured_content"]["email_body_preview"],
            "로그인해주세요",
        )
        self.assertIn(
            "credential_request",
            result["social_engineering_categories"],
        )
        self.assertEqual(result["risk_score"], 20)

    def test_wifi_password_is_redacted_from_api_result(self):
        result = main.ensure_analysis_contract(
            analyze_non_url_qr(
                "WIFI:T:WPA;S:FreeWifi;P:secret123;;"
            )
        )
        structured = result["structured_content"]

        self.assertEqual(result["qr_type"], "wifi")
        self.assertEqual(structured["wifi_security_type"], "WPA")
        self.assertEqual(structured["wifi_ssid_preview"], "FreeWifi")
        self.assertFalse(structured["wifi_hidden"])
        self.assertTrue(structured["wifi_has_password"])
        self.assertTrue(result["analysis_flags"]["has_structured_wifi"])
        self.assertNotIn("secret123", repr(result))
        self.assertIn("P:****", result["raw_content_preview"])
        QRAnalyzeResponse.model_validate(result)

    def test_open_wifi_reports_no_password(self):
        result = analyze_non_url_qr("WIFI:T:nopass;S:Guest;;")

        self.assertEqual(
            result["structured_content"]["wifi_security_type"],
            "nopass",
        )
        self.assertFalse(result["structured_content"]["wifi_has_password"])

    def test_wifi_escape_characters_are_parsed_without_password_exposure(self):
        result = analyze_non_url_qr(
            r"WIFI:T:WPA;S:Office\;Guest\:5G;P:pa\\ss\;word;H:true;;"
        )
        structured = result["structured_content"]

        self.assertEqual(structured["wifi_ssid_preview"], "Office;Guest:5G")
        self.assertTrue(structured["wifi_hidden"])
        self.assertTrue(structured["wifi_has_password"])
        self.assertNotIn("pa\\ss", repr(result))
        self.assertNotIn("word", result["raw_content_preview"])

    def test_malformed_structured_qr_never_raises(self):
        for content, expected_type in (
            ("tel:", "phone"),
            ("sms:", "sms"),
            ("mailto:", "email"),
            ("WIFI:", "wifi"),
            ("WIFI:T:WPA;S:broken\\", "wifi"),
        ):
            with self.subTest(content=content):
                result = main.ensure_analysis_contract(
                    analyze_non_url_qr(content)
                )
                self.assertEqual(result["qr_type"], expected_type)
                QRAnalyzeResponse.model_validate(result)

    def test_sms_body_url_uses_embedded_url_analyzer(self):
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
                QRAnalyzeRequest(
                    content=(
                        "sms:01012345678?"
                        "body=로그인하세요%20https://example.com"
                    )
                )
            )

        self.assertEqual(result["qr_type"], "sms")
        self.assertTrue(result["contains_url"])
        self.assertEqual(result["embedded_url_count"], 1)
        self.assertEqual(result["analyzed_embedded_url_count"], 1)
        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], "https://example.com")
        self.assertEqual(
            cache_mock.call_args.kwargs["analysis_context"],
            "embedded",
        )
        db_mock.assert_called_once()

    def test_sms_encoded_body_preserves_embedded_url_query(self):
        expected_url = "https://example.com/login?a=1&next=admin"
        content = (
            "sms:01012345678?"
            "body=https%3A%2F%2Fexample.com%2Flogin%3F"
            "a%3D1%26next%3Dadmin"
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], expected_url)
        self.assertEqual(
            result["structured_content"]["sms_body_preview"],
            expected_url,
        )
        self.assertEqual(result["embedded_url_results"][0]["url"], expected_url)

    def test_sms_encoded_korean_body_preserves_url_query(self):
        expected_url = "https://example.com/login?a=1&b=2"
        content = (
            "sms:?body=%EA%B8%B4%EA%B8%89%20"
            "https%3A%2F%2Fexample.com%2Flogin%3Fa%3D1%26b%3D2"
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], expected_url)
        self.assertEqual(
            result["structured_content"]["sms_body_preview"],
            f"긴급 {expected_url}",
        )
        self.assertIn("urgency", result["social_engineering_categories"])

    def test_sms_encoded_url_fragment_is_preserved(self):
        expected_url = "https://example.com/login?a=1#verification"
        content = (
            "sms:01012345678?body="
            "https%3A%2F%2Fexample.com%2Flogin%3Fa%3D1%23verification"
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], expected_url)
        self.assertEqual(result["embedded_url_results"][0]["url"], expected_url)

    def test_mailto_encoded_fields_preserve_body_url_query(self):
        expected_url = "https://example.com/reset?token=abc&next=home"
        content = (
            "mailto:user@example.com?"
            "subject=%EA%B3%84%EC%A0%95%20%ED%99%95%EC%9D%B8&"
            "body=https%3A%2F%2Fexample.com%2Freset%3F"
            "token%3Dabc%26next%3Dhome"
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        structured = result["structured_content"]
        self.assertEqual(structured["email_subject_preview"], "계정 확인")
        self.assertEqual(structured["email_body_preview"], expected_url)
        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], expected_url)

    def test_smsto_encoded_body_preserves_embedded_url_query(self):
        expected_url = "https://example.com/a?x=1&y=2"
        content = (
            "SMSTO:01012345678:"
            "https%3A%2F%2Fexample.com%2Fa%3Fx%3D1%26y%3D2"
        )
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        self.assertEqual(
            result["structured_content"]["sms_body_preview"],
            expected_url,
        )
        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], expected_url)

    def test_malformed_structured_percent_encoding_does_not_fail(self):
        for content in (
            "sms:01012345678?body=%E0%A4%A",
            "mailto:user@example.com?subject=%ZZ&body=%E0%A4%A",
            "SMSTO:01012345678:%E0%A4%A",
        ):
            with self.subTest(content=content.split(":", 1)[0]):
                with (
                    patch("app.main.analyze_url_with_cache") as cache_mock,
                    patch(
                        "app.main.save_scan_result",
                        return_value=make_db_result(),
                    ),
                ):
                    result = main.analyze_qr(QRAnalyzeRequest(content=content))

                self.assertIn(result["qr_type"], {"sms", "email"})
                cache_mock.assert_not_called()
                QRAnalyzeResponse.model_validate(result)

    def test_double_encoded_full_url_still_uses_direct_url_path(self):
        encoded = "https%253A%252F%252Fexample.com"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(QRAnalyzeRequest(content=encoded))

        self.assertEqual(result["qr_type"], "url")
        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], "https://example.com")

    def test_sms_without_body_url_does_not_call_url_analyzer(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content="SMSTO:01012345678:안녕하세요")
            )

        self.assertEqual(result["qr_type"], "sms")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["embedded_url_count"], 0)
        self.assertEqual(result["embedded_url_results"], [])
        cache_mock.assert_not_called()
        db_mock.assert_called_once()

    def test_sms_parent_score_and_embedded_score_use_max(self):
        url = "https://example.com"
        cases = ((55, 10, 55, "warning"), (35, 80, 80, "danger"))

        for parent_score, url_score, expected, status in cases:
            with self.subTest(parent_score=parent_score, url_score=url_score):
                with (
                    patch(
                        "app.main.analyze_non_url_qr",
                        return_value=make_structured_parent_result(
                            "sms", [url], parent_score
                        ),
                    ),
                    patch(
                        "app.main.analyze_url_with_cache",
                        return_value=make_scored_url_result(url, url_score),
                    ) as cache_mock,
                    patch(
                        "app.main.save_scan_result",
                        return_value=make_db_result(),
                    ) as db_mock,
                ):
                    result = main.analyze_qr(
                        QRAnalyzeRequest(content=f"SMSTO:01012345678:{url}")
                    )

                self.assertEqual(result["local_score"], parent_score)
                self.assertEqual(result["vt_score_delta"], 0)
                self.assertEqual(result["embedded_url_max_score"], url_score)
                self.assertEqual(result["final_score"], expected)
                self.assertEqual(result["risk_score"], expected)
                self.assertEqual(result["status"], status)
                cache_mock.assert_called_once()
                db_mock.assert_called_once()

    def test_mail_body_url_is_analyzed_but_subject_and_address_are_not(self):
        body_url = "https://body.example/login"
        content = (
            "mailto:user@example.com?"
            "subject=https://subject.example/ignore&"
            f"body={body_url}"
        )
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
            result = main.analyze_qr(QRAnalyzeRequest(content=content))

        self.assertEqual(result["qr_type"], "email")
        self.assertEqual(result["embedded_url_count"], 1)
        self.assertEqual(result["embedded_url_results"][0]["url"], body_url)
        cache_mock.assert_called_once()
        self.assertEqual(cache_mock.call_args.args[0], body_url)
        self.assertEqual(
            cache_mock.call_args.kwargs["analysis_context"],
            "embedded",
        )
        db_mock.assert_called_once()

    def test_email_parent_score_and_embedded_score_use_max(self):
        url = "https://example.com/login"
        for parent_score, url_score, expected in ((60, 10, 60), (20, 80, 80)):
            with self.subTest(parent_score=parent_score, url_score=url_score):
                with (
                    patch(
                        "app.main.analyze_non_url_qr",
                        return_value=make_structured_parent_result(
                            "email", [url], parent_score
                        ),
                    ),
                    patch(
                        "app.main.analyze_url_with_cache",
                        return_value=make_scored_url_result(url, url_score),
                    ),
                    patch(
                        "app.main.save_scan_result",
                        return_value=make_db_result(),
                    ),
                ):
                    result = main.analyze_qr(
                        QRAnalyzeRequest(
                            content=f"mailto:user@example.com?body={url}"
                        )
                    )

                self.assertEqual(result["local_score"], parent_score)
                self.assertEqual(result["vt_score_delta"], 0)
                self.assertEqual(result["final_score"], expected)

    def test_structured_body_urls_are_deduplicated_and_limited(self):
        duplicate = "https://duplicate.example/path"
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            duplicate_result = main.analyze_qr(
                QRAnalyzeRequest(
                    content=f"SMSTO:01012345678:{duplicate} {duplicate} {duplicate}"
                )
            )

        self.assertEqual(duplicate_result["embedded_url_count"], 1)
        cache_mock.assert_called_once()

        urls = [f"https://site{index}.example/path" for index in range(4)]
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=lambda url, **_: make_url_result(url),
            ) as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            limited_result = main.analyze_qr(
                QRAnalyzeRequest(
                    content="mailto:user@example.com?body=" + " ".join(urls)
                )
            )

        self.assertEqual(limited_result["embedded_url_count"], 4)
        self.assertEqual(limited_result["analyzed_embedded_url_count"], 3)
        self.assertEqual(cache_mock.call_count, 3)

    def test_structured_embedded_failure_preserves_parent_result(self):
        with (
            patch(
                "app.main.analyze_url_with_cache",
                side_effect=RuntimeError("internal failure"),
            ) as cache_mock,
            patch("app.main.logger.warning") as log_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(
                    content="SMSTO:01012345678:인증번호 https://example.com"
                )
            )

        self.assertEqual(result["qr_type"], "sms")
        self.assertEqual(result["final_score"], result["text_score"])
        self.assertEqual(result["analyzed_embedded_url_count"], 0)
        self.assertNotIn("internal failure", repr(result))
        cache_mock.assert_called_once()
        log_mock.assert_called_once()
        db_mock.assert_called_once()

    def test_sms_schemeless_body_does_not_call_url_analyzer(self):
        with (
            patch("app.main.analyze_url_with_cache") as cache_mock,
            patch("app.main.save_scan_result", return_value=make_db_result()),
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(
                    content="SMSTO:01012345678:example.com/login"
                )
            )

        self.assertEqual(result["qr_type"], "sms")
        self.assertTrue(result["contains_url_candidate"])
        self.assertEqual(result["embedded_url_count"], 0)
        cache_mock.assert_not_called()

    def test_sms_fresh_embedded_cache_hit_skips_url_analyzer_and_scan_counter(self):
        url = "https://example.com"
        cached = make_cache_item(
            url,
            checked_at=950,
            direct_history_initialized=False,
        )
        with (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(url_cache, "_utc_epoch_seconds", return_value=1000),
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                return_value=cached,
            ),
            patch.object(url_cache, "record_cached_url_scan") as scan_mock,
            patch("app.main.analyze_url") as analyzer_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content=f"SMSTO:01012345678:{url}")
            )

        analyzer_mock.assert_not_called()
        scan_mock.assert_not_called()
        db_mock.assert_called_once()
        self.assertTrue(result["embedded_url_results"][0]["cache_hit"])

    def test_sms_embedded_cache_miss_saves_only_parent_history(self):
        url = "https://example.com"
        with (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(url_cache, "_utc_epoch_seconds", return_value=1000),
            patch.object(url_cache, "get_cached_url_analysis", return_value=None),
            patch.object(url_cache, "save_cached_url_analysis") as cache_save_mock,
            patch("app.main.analyze_url", side_effect=make_url_result) as analyzer_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            result = main.analyze_qr(
                QRAnalyzeRequest(content=f"SMSTO:01012345678:{url}")
            )

        analyzer_mock.assert_called_once_with(url)
        cache_save_mock.assert_called_once()
        self.assertFalse(cache_save_mock.call_args.kwargs["increment_scan"])
        self.assertFalse(
            cache_save_mock.call_args.kwargs["direct_history_initialized"]
        )
        db_mock.assert_called_once()
        self.assertEqual(db_mock.call_args.args[0]["qr_type"], "sms")
        self.assertNotIn("_history_should_save", result)

    def test_sms_embedded_cache_then_direct_scan_preserves_initial_history(self):
        url = "https://example.com"
        state = {"item": None}

        def get_cached(_url):
            return dict(state["item"]) if state["item"] else None

        def save_cached(value, _analysis_result, **kwargs):
            item = make_cache_item(value, checked_at=1000)
            item["direct_history_initialized"] = kwargs.get(
                "direct_history_initialized"
            )
            state["item"] = item

        def record_scan(_url_hash, *, scanned_at):
            state["item"]["scan_count"] = state["item"].get("scan_count", 0) + 1
            state["item"]["last_scanned_at"] = scanned_at
            state["item"]["direct_history_initialized"] = True

        with (
            patch.object(url_cache, "URL_CACHE_ENABLED", True),
            patch.object(url_cache, "_utc_epoch_seconds", return_value=1000),
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
            patch("app.main.analyze_url", side_effect=make_url_result) as analyzer_mock,
            patch(
                "app.main.save_scan_result",
                return_value=make_db_result(),
            ) as db_mock,
        ):
            parent = main.analyze_qr(
                QRAnalyzeRequest(content=f"SMSTO:01012345678:{url}")
            )
            direct = main.analyze_qr(QRAnalyzeRequest(content=url))

        self.assertEqual(parent["qr_type"], "sms")
        self.assertEqual(direct["history_event_type"], "initial_analysis")
        self.assertTrue(direct["history_saved"])
        analyzer_mock.assert_called_once_with(url)
        self.assertEqual(db_mock.call_count, 2)
        self.assertEqual(db_mock.call_args_list[0].args[0]["qr_type"], "sms")
        self.assertEqual(
            db_mock.call_args_list[1].args[0]["history_event_type"],
            "initial_analysis",
        )

    def test_malformed_ipv6_is_client_error_without_internal_detail(self):
        with self.assertRaises(HTTPException) as raised:
            main.analyze_qr(QRAnalyzeRequest(content="http://[::1"))

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "유효하지 않은 HTTP(S) URL입니다.")
        self.assertNotIn("Invalid IPv6", raised.exception.detail)

    def test_malformed_ports_remain_controlled_client_errors(self):
        for content in (
            "https://example.com:abc",
            "https://example.com:99999",
        ):
            with self.subTest(content=content):
                with self.assertRaises(HTTPException) as raised:
                    main.analyze_qr(QRAnalyzeRequest(content=content))

                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(
                    raised.exception.detail,
                    "유효하지 않은 HTTP(S) URL입니다.",
                )

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

    def test_ruleset_reclassification_exposes_saved_history_event(self):
        analysis_result = make_url_result("https://example.com")
        analysis_result.update(
            {
                "_history_should_save": True,
                "_history_event_type": "ruleset_reclassified",
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

        self.assertEqual(
            db_mock.call_args.args[0]["history_event_type"],
            "ruleset_reclassified",
        )
        self.assertTrue(result["history_saved"])
        self.assertEqual(
            result["history_event_type"],
            "ruleset_reclassified",
        )

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
                "ruleset_version": RULESET_VERSION,
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

    def test_candidate_db_stores_only_summary_metadata(self):
        class CapturingTable:
            item = None

            def put_item(self, *, Item):
                self.item = Item

        result = main.ensure_analysis_contract(analyze_non_url_qr("example.com"))
        table = CapturingTable()
        with (
            patch.object(database, "DYNAMODB_ENABLED", True),
            patch("app.services.database._get_table", return_value=table),
        ):
            database.save_scan_result(result)

        self.assertTrue(table.item["contains_url_candidate"])
        self.assertEqual(table.item["candidate_url_count"], 1)
        self.assertNotIn("extracted_url_candidates", table.item)

    def test_structured_qr_db_stores_only_non_sensitive_summary(self):
        class CapturingTable:
            item = None

            def put_item(self, *, Item):
                self.item = Item

        cases = (
            (
                "tel:01012345678",
                ("01012345678",),
                {},
            ),
            (
                "sms:01012345678?body=긴급 로그인 확인",
                ("01012345678", "긴급 로그인 확인"),
                {"sms_body_length": 9},
            ),
            (
                "mailto:user@example.com?body=로그인해주세요",
                ("user@example.com", "로그인해주세요"),
                {"email_domain": "example.com", "email_body_length": 7},
            ),
            (
                "WIFI:T:WPA;S:PrivateNetwork;P:secret123;H:true;;",
                ("PrivateNetwork", "secret123"),
                {
                    "wifi_security_type": "WPA",
                    "wifi_hidden": True,
                    "wifi_has_password": True,
                },
            ),
        )

        for content, forbidden_values, expected_summary in cases:
            with self.subTest(content=content.split(":", 1)[0]):
                result = main.ensure_analysis_contract(
                    analyze_non_url_qr(content)
                )
                table = CapturingTable()
                with (
                    patch.object(database, "DYNAMODB_ENABLED", True),
                    patch(
                        "app.services.database._get_table",
                        return_value=table,
                    ),
                ):
                    database.save_scan_result(result)

                self.assertNotIn("structured_content", table.item)
                self.assertNotIn("phone_number_masked", table.item)
                self.assertNotIn("sms_recipient_masked", table.item)
                self.assertNotIn("sms_body_preview", table.item)
                self.assertNotIn("email_address_masked", table.item)
                self.assertNotIn("email_body_preview", table.item)
                self.assertNotIn("wifi_ssid_preview", table.item)
                for forbidden in forbidden_values:
                    self.assertNotIn(forbidden, repr(table.item))
                for key, expected in expected_summary.items():
                    self.assertEqual(table.item[key], expected)

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
            "ruleset_version": RULESET_VERSION,
            "analysis_flags": {},
        }

        dashboard_item = database._make_dashboard_item(item)
        self.assertEqual(dashboard_item["qr_type"], "text")
        self.assertFalse(dashboard_item["contains_url"])
        self.assertEqual(dashboard_item["final_score"], 0)
        self.assertEqual(dashboard_item["ruleset_version"], RULESET_VERSION)
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
            ruleset_version="1.0",
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
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
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
            ruleset_version="1.0",
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
        self.assertEqual(
            result["_history_event_type"],
            "ruleset_reclassified",
        )

    def test_ruleset_change_with_status_change_requests_reclassification(self):
        cached = make_cache_item(
            "https://example.com",
            checked_at=990,
            ruleset_version="1.0",
            local_score=55,
            final_score=55,
            risk_score=55,
            status="warning",
        )
        current = make_scored_url_result("https://example.com", 55)
        current["status"] = "danger"

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
                analyzer=Mock(return_value=current),
                now_epoch=1000,
            )

        self.assertTrue(result["_history_should_save"])
        self.assertEqual(
            result["_history_event_type"],
            "ruleset_reclassified",
        )

    def test_ruleset_change_with_new_punycode_score_requests_history(self):
        url = "https://xn--example-xxxx.com"
        cached = make_cache_item(
            url,
            checked_at=990,
            ruleset_version="1.0",
        )
        current = analyze_url_with_vt_result(
            url,
            {"enabled": False, "available": False},
        )

        with (
            patch.object(
                url_cache,
                "get_cached_url_analysis",
                return_value=cached,
            ),
            patch.object(url_cache, "save_cached_url_analysis") as save_mock,
        ):
            result = url_cache.analyze_url_with_cache(
                url,
                analyzer=Mock(return_value=current),
                now_epoch=1000,
            )

        save_mock.assert_called_once()
        self.assertEqual(result["revalidation_reason"], "ruleset_changed")
        self.assertEqual(result["local_score"], 25)
        self.assertTrue(result["_history_should_save"])
        self.assertEqual(
            result["_history_event_type"],
            "ruleset_reclassified",
        )

    def test_ruleset_change_with_vt_disabled_keeps_historical_vt_risk(self):
        cached_result = make_vt_url_result("https://example.com", malicious=3)
        cached = make_cache_item(
            "https://example.com",
            checked_at=800,
            ruleset_version="1.0",
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
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
        self.assertEqual(result["status"], "danger")
        self.assertEqual(result["final_score"], 80)
        self.assertFalse(result["cache_revalidated"])
        self.assertEqual(save_mock.call_args.kwargs["last_checked_at"], 800)
        self.assertFalse(result["_history_should_save"])


if __name__ == "__main__":
    unittest.main()
