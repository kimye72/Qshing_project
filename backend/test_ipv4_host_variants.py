"""Browser numeric IPv4 hosts: local scoring and real API/cache paths offline."""
import copy
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

from fastapi.testclient import TestClient

from app import main
from app.constants import EMBEDDED_URL_POLICY_VERSION, RULESET_VERSION
from app.services import scanner, url_cache
from test_analyze_qr import make_cache_item
import test_official_domain_insertion as brand_tests


class BrowserIpv4Tests(unittest.TestCase):
    INTERNAL = (
        ("127.0.0.1", "127.0.0.1"), ("127.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"), ("0x7f000001", "127.0.0.1"),
        ("0300.0250.1.1", "192.168.1.1"),
        ("127.0.1", "127.0.0.1"), ("0X7F.0.0.01", "127.0.0.1"),
        ("127.1.", "127.0.0.1"), ("192.168.257", "192.168.1.1"),
        ("192.11010305", "192.168.1.1"), ("0xc0a80101", "192.168.1.1"),
        ("3232235777", "192.168.1.1"),
    )
    PUBLIC = (
        "8.8.8.8", "134744072", "0x08080808", "010.010.010.010",
        "8.8.2056", "8.526344", "8.0x8.010.8",
    )

    def setUp(self):
        # Real URL/cache/API code, with only external VT/storage operations mocked.
        brand_tests.OfficialDomainInsertionTests.setUp(self)

    def assert_ip(self, result, *, private=True, score=85, status="danger"):
        self.assertEqual((result["local_score"], result["final_score"], result["status"]),
                         (score, score, status))
        self.assertTrue(result["analysis_flags"]["ip_address_host"])
        self.assertIs(result["analysis_flags"]["private_or_local_host"], private)
        self.assertFalse(result["analysis_flags"]["excessive_hostname_labels"])
        self.assertEqual(result["ruleset_version"], "1.6")

    def old_cache(self, url, version="1.5", malicious=0):
        cached = make_cache_item(
            url, checked_at=990, ruleset_version=version,
            local_score=10, final_score=80 if malicious else 10,
            risk_score=80 if malicious else 10, vt_score_delta=70 if malicious else 0,
            status="danger" if malicious else "safe",
            analysis_flags={"ip_address_host": False, "private_or_local_host": False},
            reasons=["특별한 위험 요소가 발견되지 않았습니다."],
            vt_available=bool(malicious), vt_malicious=malicious,
            vt_source="url_report" if malicious else None,
            vt_lookup_status="available" if malicious else "disabled",
        )
        if version is None:
            cached.pop("ruleset_version")
        if malicious:
            cached["vt_checked_at"] = 900
        return cached

    def test_internal_variants_match_standard_address_score_flags_and_reasons(self):
        self.assertEqual(RULESET_VERSION, "1.6")
        self.assertEqual(EMBEDDED_URL_POLICY_VERSION, "2.1")
        for host, canonical in self.INTERNAL:
            with self.subTest(host=host):
                self.assertEqual(str(scanner._parse_whatwg_ipv4(host)), canonical)
                result = scanner.analyze_url("https://" + host + "/")
                standard = scanner.analyze_url("https://" + canonical + "/")
                self.assert_ip(result)
                self.assertEqual(result["analysis_flags"], standard["analysis_flags"])
                self.assertEqual(result["reasons"], standard["reasons"])
                self.assertEqual(result["url"], "https://" + host + "/")

    def test_public_variants_receive_only_existing_ip_addition(self):
        standard = scanner.analyze_url("https://8.8.8.8/")
        for host in self.PUBLIC:
            with self.subTest(host=host):
                self.assertEqual(str(scanner._parse_whatwg_ipv4(host)), "8.8.8.8")
                result = scanner.analyze_url("https://" + host + "/")
                self.assert_ip(result, private=False, score=35, status="warning")
                self.assertEqual(result["reasons"], standard["reasons"])

    def test_numeric_syntax_range_failures_are_distinct_from_ordinary_domains(self):
        invalid = (
            "09", "127.09", "0xGG.1", "1..2", ".127.1", "1.2.3.4.5",
            "256.1", "1.16777216", "1.2.65536", "1.2.3.256",
            "4294967296", "0x100000000", "040000000000",
            "-1.1", "+1.1", "example.123", "9" * 5000,
        )
        for host in invalid:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    scanner._parse_whatwg_ipv4(host)
                self.assertEqual(scanner._is_ip_address(host), (False, False))
        for host in (
            "example.com", "127.example.com", "123example.invalid", "127.1.evil.invalid",
            "0x7f000001.evil.invalid", "2130706433.invalid", "v1.2.example",
            "0xGG", "123abc", "127.1..", "１２７.１", "-1", "+1",
        ):
            with self.subTest(host=host):
                self.assertIsNone(scanner._parse_whatwg_ipv4(host))
                result = scanner.analyze_url("https://" + host + "/")
                self.assertFalse(result["analysis_flags"]["ip_address_host"])
                self.assertFalse(result["analysis_flags"]["private_or_local_host"])
        for host in ("09", "256.1", "1.2.3.256", "4294967296", "example.123"):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host + "/")
                self.assertFalse(result["analysis_flags"]["ip_address_host"])
                self.assertFalse(result["analysis_flags"]["private_or_local_host"])

    def test_number_parser_boundaries_and_nondecimal_zero(self):
        for host, canonical in (
            ("0", "0.0.0.0"), ("0x", "0.0.0.0"), ("0X", "0.0.0.0"),
            ("00", "0.0.0.0"), ("127.0x", "127.0.0.0"),
            ("4294967295", "255.255.255.255"),
            ("0xFFFFFFFF", "255.255.255.255"),
            ("037777777777", "255.255.255.255"),
            ("1.16777215", "1.255.255.255"),
            ("1.2.65535", "1.2.255.255"),
        ):
            with self.subTest(host=host):
                self.assertEqual(str(scanner._parse_whatwg_ipv4(host)), canonical)

    def test_original_hosts_ipv6_localhost_and_brand_rules_remain(self):
        for host, score, is_ip, private in (
            ("192.168.1.1", 85, True, True), ("[::1]", 85, True, True),
            ("[fd00::1]", 85, True, True), ("[fe80::1]", 85, True, True),
            ("[2001:4860:4860::8888]", 35, True, False),
            ("localhost", 60, False, True), ("device.local", 60, False, True),
            ("google.com.au", 10, False, False), ("apple.com.cn", 10, False, False),
            ("kakaopay.com", 10, False, False), ("naver.me", 30, False, False),
            ("kakaopay.com.evil.invalid", 35, False, False),
        ):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host + "/")
                self.assertEqual(result["local_score"], score)
                self.assertIs(result["analysis_flags"]["ip_address_host"], is_ip)
                self.assertIs(result["analysis_flags"]["private_or_local_host"], private)

    def test_ip_inspection_uses_host_only_and_preserves_other_risk_rules(self):
        for url, score in (
            ("http://127.1/", 105), ("https://user@127.1/", 110),
            ("https://127.1:8443/", 95), ("https://127.1/?q=<script>", 95),
            ("https://127.1/?q=select", 95), ("https://%31%32%37.1/", 90),
        ):
            with self.subTest(url=url):
                result = scanner.analyze_url(url)
                self.assertEqual(result["local_score"], score)
                self.assertEqual(result["final_score"], min(score, 100))
                self.assertTrue(result["analysis_flags"]["ip_address_host"])
                self.assertTrue(result["analysis_flags"]["private_or_local_host"])
                self.assertEqual(result["url"], url)
        self.assertEqual(scanner._is_ip_address("127.1", allow_browser_ipv4=False), (False, False))
        for url in ("https://example.com/127.1?next=0x7f000001#2130706433",
                    "https://127.1@example.com/"):
            result = scanner.analyze_url(url)
            self.assertFalse(result["analysis_flags"]["ip_address_host"])
            self.assertFalse(result["analysis_flags"]["private_or_local_host"])
        vt = {"enabled": True, "available": True, "source": "url_report",
              "lookup_status": "available", "stats": {"malicious": 3}}
        result = scanner.analyze_url_with_vt_result("https://134744072/", vt)
        self.assertEqual((result["local_score"], result["vt_score_delta"], result["final_score"]),
                         (35, 70, 100))
        self.assertTrue(any("악성 3건" in reason for reason in result["reasons"]))
        self.assertNotIn("특별한 위험 요소가 발견되지 않았습니다.", result["reasons"])

    def test_real_direct_and_body_api_responses_preserve_exact_addresses(self):
        with TestClient(main.app) as client:
            for host, _ in self.INTERNAL[:5]:
                address = f"https://{host}/배송?Token=Ab%26Cd+E#부분%23"
                for path in ("/scan", "/analyze-qr"):
                    response = client.post(path, json={"url" if path == "/scan" else "content": address})
                    self.assertEqual(response.status_code, 200)
                    self.assert_ip(response.json(), score=90)
                    self.assertEqual(response.json()["url"], address)
                for content in ("확인: " + address, "SMS:+821012345678:" + address,
                                "sms:+821012345678?body=" + quote("확인: " + address, safe="")):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    parent = response.json()
                    child = parent["embedded_url_results"][0]
                    self.assert_ip(child, score=90)
                    self.assertEqual(child["analysis_url"], address)
                    self.assertEqual(child["url"], address)
                    self.assertEqual(child["original_url"], address)
                    self.assertEqual(child["original_candidates"], [])
                    self.assertFalse(child["assumed_https"])
                    self.assertEqual(parent["final_score"], max(parent["text_score"], 90))
                    self.assertEqual(parent["embedded_url_policy_version"], "2.1")

    def test_15_and_missing_versions_recalculate_real_scores_in_both_contexts(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True):
            for url in ("https://127.1/", "https://134744072/"):
                for version in ("1.5", None):
                    for context in ("direct", "embedded"):
                        with self.subTest(url=url, version=version, context=context):
                            cached = self.old_cache(url, version)
                            before = copy.deepcopy(cached)
                            self.lookup.return_value = cached
                            self.write.reset_mock()
                            analyzer = Mock(wraps=scanner.analyze_url)
                            result = url_cache.analyze_url_with_cache(url, analyzer=analyzer, analysis_context=context)
                            analyzer.assert_called_once_with(url)
                            self.assert_ip(result, private="127" in url,
                                           score=85 if "127" in url else 35,
                                           status="danger" if "127" in url else "warning")
                            self.assertEqual(result["revalidation_reason"], "ruleset_changed")
                            self.assertEqual(self.write.call_args.args[1]["ruleset_version"], "1.6")
                            self.assertEqual(cached, before)

    def test_current_cache_reuses_flags_without_changing_analysis_address(self):
        url = "https://0x7f000001/Path?Token=AbC#Part"
        current = scanner.analyze_url(url)
        cached = make_cache_item(url, checked_at=990, **{
            key: current[key] for key in url_cache._CACHE_RESULT_FIELDS
        })
        self.lookup.return_value = cached
        self.vt.reset_mock()
        self.write.reset_mock()
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            with patch.object(main, "analyze_url", side_effect=AssertionError("must reuse current cache")):
                for content in (url, "확인: " + url, "SMSTO:+821012345678:" + url):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    parent = response.json()
                    result = parent["embedded_url_results"][0] if parent["embedded_url_results"] else parent
                    self.assert_ip(result)
                    self.assertTrue(result["cache_hit"])
                    self.assertEqual(result.get("analysis_url", result["url"]), url)
        self.vt.assert_not_called()
        self.write.assert_not_called()

    def test_old_cache_api_returns_current_ip_score_for_direct_and_sms(self):
        url = "https://127.1/Path?Token=AbC#Part"
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            for version in ("1.5", None):
                cached = self.old_cache(url, version)
                before = copy.deepcopy(cached)
                self.lookup.return_value = cached
                with patch.object(main, "analyze_url", wraps=scanner.analyze_url) as analyzer:
                    for path, payload in (
                        ("/scan", {"url": url}), ("/analyze-qr", {"content": url}),
                        ("/analyze-qr", {"content": "확인: " + url}),
                        ("/analyze-qr", {"content": "SMS:+821012345678?body=" + quote(url, safe="")}),
                    ):
                        response = client.post(path, json=payload)
                        self.assertEqual(response.status_code, 200)
                        parent = response.json()
                        result = parent["embedded_url_results"][0] if parent.get("embedded_url_results") else parent
                        self.assert_ip(result)
                        self.assertEqual(result["revalidation_reason"], "ruleset_changed")
                        self.assertEqual(result.get("analysis_url", result["url"]), url)
                    self.assertEqual(analyzer.call_count, 4)
                self.assertEqual(cached, before)

    def test_recalculation_failure_keeps_old_cache_and_partial_qr_result(self):
        url = "https://127.1/"
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            for version in ("1.5", None):
                cached = self.old_cache(url, version)
                before = copy.deepcopy(cached)
                self.lookup.side_effect = lambda address: cached if address == url else None
                self.write.reset_mock()
                with patch.object(main, "analyze_url", side_effect=RuntimeError("private failure")):
                    for path in ("/scan", "/analyze-qr"):
                        response = client.post(path, json={"url" if path == "/scan" else "content": url})
                        self.assertEqual(response.status_code, 503)
                        self.assertNotIn("ruleset_version", response.json())
                        self.assertNotIn("private failure", response.text)
                self.write.assert_not_called()
                def analyze(address):
                    if address == url:
                        raise RuntimeError("private failure")
                    return scanner.analyze_url(address)
                body = "긴급 로그인 확인: " + url + " https://naver.me/AbCd1234"
                with patch.object(main, "analyze_url", side_effect=analyze):
                    response = client.post("/analyze-qr", json={"content": body})
                parent = response.json()
                self.assertEqual(response.status_code, 200)
                self.assertFalse(parent["embedded_url_analysis_complete"])
                self.assertEqual(parent["final_score"], max(parent["text_score"], 30))
                self.assertEqual(parent["embedded_url_failures"][0]["analysis_url"], url)
                self.assertEqual(parent["embedded_url_failures"][0]["error_code"], "EMBEDDED_URL_ANALYSIS_FAILED")
                self.assertEqual(parent["embedded_url_results"][0]["ruleset_version"], "1.6")
                self.assertEqual(cached, before)

    def test_old_vt_evidence_combines_with_new_local_ip_score(self):
        url = "https://134744072/"
        cached = self.old_cache(url, malicious=3)
        self.lookup.return_value = cached
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            result = client.post("/scan", json={"url": url}).json()
        self.assertEqual((result["local_score"], result["vt_score_delta"], result["final_score"]), (35, 70, 100))
        self.assertEqual(result["ruleset_version"], "1.6")
        self.assertTrue(result["analysis_flags"]["historical_reputation_used"])
        self.assertFalse(result["vt_available"])
        self.assertEqual(result["vt_source"], "cached_report")
        self.assertEqual(result["vt_malicious"], 3)
        self.assertEqual(self.write.call_args.kwargs["vt_checked_at"], 900)
        self.assertTrue(any("재조회는 완료하지 못했습니다" in reason for reason in result["reasons"]))
        self.assertNotIn("특별한 위험 요소가 발견되지 않았습니다.", result["reasons"])
        self.assertEqual(cached["ruleset_version"], "1.5")


if __name__ == "__main__":
    unittest.main()
