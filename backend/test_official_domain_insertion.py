"""Official-domain label insertion rules and real API/cache regressions, offline."""
import copy
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

from fastapi.testclient import TestClient

from app import main
from app.constants import ASSUMED_HTTPS_REASON, RULESET_VERSION
from app.services import scanner, url_cache
from app.services.brand_domains import GOOGLE_SUPPORTED_DOMAINS
from test_analyze_qr import make_cache_item, make_db_result


class OfficialDomainInsertionTests(unittest.TestCase):
    HOSTS = ("kakaopay.com.evil.invalid", "naver.me.evil.invalid", "paypal.com.evil.invalid")
    REASON = "공식 도메인 형태 뒤에 다른 호스트 라벨이 이어져 있습니다."
    GENERIC_REASON = "유명 서비스명을 포함하지만 공식 도메인으로 보기 어려운 주소입니다."

    def setUp(self):
        settings = (
            ("vt", patch.object(scanner, "get_url_report", return_value={
                "enabled": False, "available": False, "lookup_status": "disabled",
            })),
            (None, patch.object(url_cache, "URL_CACHE_ENABLED", False)),
            (None, patch.object(url_cache, "URL_CACHE_FRESHNESS_SECONDS", 100)),
            (None, patch.object(url_cache, "_utc_epoch_seconds", return_value=1000)),
            ("lookup", patch.object(url_cache, "get_cached_url_analysis", return_value=None)),
            ("write", patch.object(url_cache, "save_cached_url_analysis")),
            (None, patch.object(url_cache, "record_cached_url_scan")),
            (None, patch.object(main, "save_scan_result", return_value=make_db_result())),
            (None, patch.object(main, "mark_direct_url_history_saved")),
        )
        for name, setting in settings:
            active = setting.start()
            self.addCleanup(setting.stop)
            if name:
                setattr(self, name, active)

    def assert_insertion(self, result, score=35, status="warning"):
        self.assertEqual((result["final_score"], result["status"]), (score, status))
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
        self.assertTrue(result["analysis_flags"]["suspicious_brand_domain"])
        self.assertTrue(result["analysis_flags"]["official_domain_insertion"])
        self.assertEqual(result["reasons"].count(self.REASON), 1)
        self.assertNotIn(self.GENERIC_REASON, result["reasons"])
        self.assertNotIn("특별한 위험 요소가 발견되지 않았습니다.", result["reasons"])

    def old_cache(self, url, *, version="1.3", malicious=0):
        delta = 70 if malicious == 3 else 0
        cached = make_cache_item(
            url, checked_at=990, domain=url.split("://", 1)[1],
            ruleset_version=version, local_score=25, vt_score_delta=delta,
            final_score=25 + delta, risk_score=25 + delta,
            status="danger" if delta else "safe", reasons=[self.GENERIC_REASON],
            analysis_flags={"suspicious_brand_domain": True, "shortener": False},
            vt_available=bool(malicious), vt_malicious=malicious,
            vt_source="url_report" if malicious else None,
            vt_lookup_status="available" if malicious else "disabled",
        )
        if version is None:
            cached.pop("ruleset_version")
        if malicious:
            cached["vt_checked_at"] = 900
        return cached

    def test_representative_hosts_have_one_strengthened_brand_addition(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host)
                self.assert_insertion(result)
                self.assertEqual((result["local_score"], result["vt_score_delta"]), (35, 0))
                self.assertEqual(result["reasons"], [self.REASON])
                self.assertFalse(result["analysis_flags"]["shortener"])

    def test_case_trailing_dot_and_internal_label_boundaries(self):
        for host, score in (
            ("KAKAOPAY.COM.EVIL.INVALID.", 35),
            ("NaVeR.Me.Evil.Invalid", 35),
            ("PAYPAL.COM.EVIL.INVALID.", 35),
            ("x.paypal.com.evil.invalid", 45),
            ("google.co.kr.evil.invalid", 45),
        ):
            with self.subTest(host=host):
                self.assert_insertion(scanner.analyze_url("https://" + host), score)

    def test_official_hosts_and_existing_child_exceptions_keep_their_scores(self):
        for host, score in (
            ("kakaopay.com", 10), ("M.KAKAOPAY.COM.", 10),
            ("naver.me", 30), ("m.naver.me.", 30),
            ("paypal.com", 10), ("m.paypal.com", 10),
            # An inserted form inside this brand's real child remains exempt.
            ("paypal.com.m.paypal.com", 20),
        ):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host)
                self.assertEqual(result["local_score"], score)
                self.assertFalse(result["analysis_flags"]["suspicious_brand_domain"])
                self.assertFalse(result["analysis_flags"]["official_domain_insertion"])
                self.assertNotIn(self.REASON, result["reasons"])
                self.assertEqual(result["analysis_flags"]["shortener"], "naver.me" in host.lower())

    def test_partial_domain_labels_and_generic_brand_signals_remain_15_points(self):
        for host in (
            "fakekakaopay.invalid", "fakekakaopay.com.evil", "kakaopay.comx.evil",
            "kakaopay.com-evil.invalid", "naver.mee.evil", "fakenaver.me.evil",
            "fakepaypal.com.evil", "paypal-com.invalid", "paypal.invalid",
        ):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host)
                self.assertEqual((result["local_score"], result["status"]), (25, "safe"))
                self.assertTrue(result["analysis_flags"]["suspicious_brand_domain"])
                self.assertFalse(result["analysis_flags"]["official_domain_insertion"])
                self.assertEqual(result["reasons"], [self.GENERIC_REASON])

    def test_non_host_components_cannot_trigger_the_strengthened_rule(self):
        for url, score in (
            ("https://example.invalid/kakaopay.com.evil.invalid", 10),
            ("https://example.invalid/?next=naver.me.evil.invalid", 10),
            ("https://example.invalid/#paypal.com.evil.invalid", 10),
            ("https://paypal.com.evil.invalid@example.invalid/", 35),
            ("https://fakepaypal.invalid/?next=kakaopay.com.evil.invalid", 25),
            ("https://kakaopay.com/?next=naver.me.evil.invalid", 10),
        ):
            with self.subTest(url=url):
                result = scanner.analyze_url(url)
                self.assertEqual(result["local_score"], score)
                self.assertFalse(result["analysis_flags"]["official_domain_insertion"])
                self.assertNotIn(self.REASON, result["reasons"])

    def test_overlapping_domains_and_multiple_brands_never_stack_the_addition(self):
        for host, score in (
            ("www.paypal.com.evil.invalid", 45),
            ("naver.me.paypal.com.evil", 45),
            ("paypal.com.kakao.com.evil.invalid", 45),
            # Exceptions are per brand: Kakao's child still embeds PayPal.
            ("paypal.com.kakaopay.com", 35),
        ):
            with self.subTest(host=host):
                self.assert_insertion(scanner.analyze_url("https://" + host), score)

    def test_other_local_signals_and_vt_points_are_retained(self):
        for url, score, flag in (
            ("http://naver.me.evil.invalid", 55, "non_https"),
            ("https://user@kakaopay.com.evil.invalid", 60, "userinfo_in_url"),
            ("https://paypal.com.evil.invalid:8443", 45, "nonstandard_port"),
            ("https://x.paypal.com.evil.invalid", 45, "excessive_hostname_labels"),
            ("https://paypal.com.evil.invalid/%3Cscript%3E", 50, "decoded_changed"),
            ("https://kakaopay.com.evil.invalid/?q=union%20select", 60, "sql_xss_pattern_count"),
        ):
            with self.subTest(url=url):
                result = scanner.analyze_url(url)
                self.assert_insertion(result, score)
                self.assertTrue(result["analysis_flags"][flag])
        report = {
            "enabled": True, "available": True, "lookup_status": "available",
            "source": "url_report", "stats": {"malicious": 3, "suspicious": 0},
        }
        self.vt.return_value = report
        for host in self.HOSTS:
            url = "https://" + host
            result = scanner.analyze_url(url)
            self.assert_insertion(result, 100, "danger")
            self.assertEqual((result["local_score"], result["vt_score_delta"]), (35, 70))
            self.assertIn("VirusTotal 탐지 결과 악성 3건, 의심 0건이 확인되었습니다.", result["reasons"])
            self.assertEqual(result["reasons"], scanner.analyze_url_with_vt_result(url, report)["reasons"])

    def test_real_direct_sms_and_text_api_serialization(self):
        with TestClient(main.app) as client:
            for host in self.HOSTS:
                url = "https://" + host
                for path in ("/scan", "/analyze-qr"):
                    response = client.post(path, json={"url" if path == "/scan" else "content": url})
                    self.assertEqual(response.status_code, 200)
                    self.assert_insertion(response.json())
                for content, assumed in (
                    ("확인 " + url, False),
                    ("확인 " + host, True),
                    ("SMSTO:01012345678:확인 " + host, True),
                    ("SMS:+821012345678?body=" + quote("확인 " + url, safe=""), False),
                ):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    parent = response.json()
                    child = parent["embedded_url_results"][0]
                    self.assert_insertion(child)
                    self.assertEqual(parent["final_score"], max(parent["text_score"], 35))
                    self.assertTrue(parent["embedded_url_analysis_complete"])
                    self.assertEqual(child["analysis_url"], url)
                    self.assertEqual(child["original_url"], host if assumed else url)
                    self.assertEqual(child["assumed_https"], assumed)

    def test_old_and_missing_versions_recalculate_without_modifying_the_old_cache(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True):
            for host in self.HOSTS:
                url = "https://" + host
                for version in ("1.3", None):
                    for context in ("direct", "embedded"):
                        with self.subTest(host=host, version=version, context=context):
                            cached = self.old_cache(url, version=version)
                            before = copy.deepcopy(cached)
                            self.lookup.return_value = cached
                            analyzer = Mock(wraps=scanner.analyze_url)
                            result = url_cache.analyze_url_with_cache(url, analyzer=analyzer, analysis_context=context)
                            analyzer.assert_called_once_with(url)
                            self.assert_insertion(result)
                            self.assertEqual(result["revalidation_reason"], "ruleset_changed")
                            self.assertFalse(result["cache_hit"])
                            saved = self.write.call_args.args[1]
                            self.assertEqual((saved["ruleset_version"], saved["final_score"]), (RULESET_VERSION, 35))
                            self.assertEqual(cached, before)
                            if context == "direct":
                                self.assertTrue(result["_history_should_save"])
                                self.assertEqual(result["_history_event_type"], "ruleset_reclassified")
                            else:
                                self.assertNotIn("_history_should_save", result)

    def test_current_cache_reuse_preserves_flag_and_request_specific_https_metadata(self):
        url = "https://" + self.HOSTS[0]
        result = scanner.analyze_url(url)
        cached = make_cache_item(url, checked_at=990, **{key: result[key] for key in url_cache._CACHE_RESULT_FIELDS})
        self.lookup.return_value = cached
        self.vt.reset_mock()
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            with patch.object(main, "analyze_url", side_effect=AssertionError("must reuse current cache")):
                for content, assumed in (("확인 " + self.HOSTS[0], True), ("확인 " + url, False)):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    child = response.json()["embedded_url_results"][0]
                    self.assert_insertion(child)
                    self.assertTrue(child["cache_hit"])
                    self.assertEqual(child["assumed_https"], assumed)
                    self.assertEqual(ASSUMED_HTTPS_REASON in child["reasons"], assumed)
                direct = client.post("/scan", json={"url": url})
                self.assertEqual(direct.status_code, 200)
                self.assert_insertion(direct.json())
                self.assertEqual(direct.json()["history_skip_reason"], "duplicate_unchanged")
        self.vt.assert_not_called()
        self.write.assert_not_called()
        self.assertNotIn(ASSUMED_HTTPS_REASON, cached["reasons"])

    def test_recalculation_failure_does_not_relabel_old_results_and_keeps_partial_qr(self):
        url = "https://" + self.HOSTS[0]
        cached = self.old_cache(url)
        before = copy.deepcopy(cached)
        self.lookup.return_value = cached
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            with patch.object(main, "analyze_url", side_effect=RuntimeError("private failure")):
                for path in ("/scan", "/analyze-qr"):
                    response = client.post(path, json={"url" if path == "/scan" else "content": url})
                    self.assertEqual(response.status_code, 503)
                    self.assertNotIn("ruleset_version", response.json())
                    self.assertNotIn("private failure", response.text)
            self.write.assert_not_called()
            self.lookup.side_effect = lambda candidate: cached if candidate == url else None
            def analyze(candidate):
                if candidate == url:
                    raise RuntimeError("private failure")
                return scanner.analyze_url(candidate)
            with patch.object(main, "analyze_url", side_effect=analyze):
                response = client.post("/analyze-qr", json={"content": "SMSTO:01012345678:확인 " + self.HOSTS[0] + " https://naver.me/AbCd1234"})
            self.assertEqual(response.status_code, 200)
            parent = response.json()
            self.assertFalse(parent["embedded_url_analysis_complete"])
            self.assertEqual(parent["final_score"], max(parent["text_score"], 30))
            self.assertEqual(parent["embedded_url_results"][0]["ruleset_version"], RULESET_VERSION)
            self.assertEqual(parent["embedded_url_failures"][0]["error_code"], "EMBEDDED_URL_ANALYSIS_FAILED")
            self.assertTrue(parent["embedded_url_failures"][0]["assumed_https"])
            self.assertNotIn("private failure", response.text)
        self.assertEqual(cached, before)

    def test_old_vt_risk_combines_with_new_local_score_without_refreshing_reputation(self):
        url = "https://" + self.HOSTS[0]
        cached = self.old_cache(url, malicious=3)
        self.lookup.return_value = cached
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            response = client.post("/scan", json={"url": url})
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assert_insertion(result, 100, "danger")
        self.assertEqual((result["local_score"], result["vt_score_delta"]), (35, 70))
        self.assertFalse(result["vt_available"])
        self.assertEqual((result["vt_lookup_status"], result["vt_source"]), ("disabled", "cached_report"))
        self.assertEqual(result["vt_malicious"], 3)
        self.assertTrue(result["analysis_flags"]["historical_reputation_used"])
        self.assertTrue(any("재조회는 완료하지 못했습니다" in reason for reason in result["reasons"]))
        self.assertEqual(self.write.call_args.kwargs["vt_checked_at"], 900)
        self.assertEqual(result["history_event_type"], "ruleset_reclassified")
        self.assertTrue(result["history_saved"])
        self.assertEqual(cached["ruleset_version"], "1.3")


class OfficialCountryDomainTests(unittest.TestCase):
    URLS = ("https://google.com.au", "https://apple.com.cn")
    INSERTION_REASON = OfficialDomainInsertionTests.REASON

    def setUp(self):
        OfficialDomainInsertionTests.setUp(self)

    def assert_official(self, result, score=10, status="safe"):
        self.assertEqual((result["final_score"], result["status"]), (score, status))
        self.assertEqual(result["ruleset_version"], RULESET_VERSION)
        self.assertFalse(result["analysis_flags"]["suspicious_brand_domain"])
        self.assertFalse(result["analysis_flags"]["official_domain_insertion"])
        self.assertNotIn(self.INSERTION_REASON, result["reasons"])
        self.assertNotIn(OfficialDomainInsertionTests.GENERIC_REASON, result["reasons"])

    def old_cache(self, url, *, version="1.4", malicious=0):
        delta = 70 if malicious == 3 else 0
        cached = make_cache_item(
            url, checked_at=990, domain=url.split("://", 1)[1],
            ruleset_version=version, local_score=35, vt_score_delta=delta,
            final_score=min(35 + delta, 100), risk_score=min(35 + delta, 100),
            status="danger" if delta else "warning", reasons=[self.INSERTION_REASON],
            analysis_flags={"suspicious_brand_domain": True, "official_domain_insertion": True},
            vt_available=bool(malicious), vt_malicious=malicious,
            vt_source="url_report" if malicious else None,
            vt_lookup_status="available" if malicious else "disabled",
        )
        if version is None:
            cached.pop("ruleset_version")
        if malicious:
            cached["vt_checked_at"] = 900
        return cached

    def test_country_hosts_case_trailing_dot_and_children_drop_to_ten(self):
        self.assertEqual(RULESET_VERSION, "1.6")
        for host in (
            "google.com.au", "apple.com.cn", "GOOGLE.COM.AU.", "APPLE.COM.CN.",
            "www.google.com.au", "www.apple.com.cn", "m.google.com.au", "m.apple.com.cn",
        ):
            with self.subTest(host=host):
                self.assert_official(scanner.analyze_url("https://" + host))
                # Even direct insertion checks must exempt the longer domain.
                self.assertFalse(scanner._has_official_domain_insertion(host))

    def test_every_explicit_google_snapshot_host_and_child_is_exempt(self):
        self.assertEqual(len(GOOGLE_SUPPORTED_DOMAINS), 187)
        self.assertEqual(len(set(GOOGLE_SUPPORTED_DOMAINS)), 187)
        self.assertIn("google.com.au", GOOGLE_SUPPORTED_DOMAINS)
        for domain in GOOGLE_SUPPORTED_DOMAINS:
            for host in (domain, "WWW." + domain.upper() + "."):
                with self.subTest(host=host):
                    self.assert_official(scanner.analyze_url("https://" + host))

    def test_country_domains_with_other_host_labels_keep_single_strengthened_addition(self):
        for host in (
            "google.com.au.evil.invalid", "apple.com.cn.evil.invalid",
            "GOOGLE.COM.AU.EVIL.INVALID.", "APPLE.COM.CN.EVIL.INVALID.",
            "google.com.au.apple.com.cn.evil", "www.google.com.au.evil.invalid",
        ):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host)
                self.assertEqual((result["local_score"], result["status"]), (45, "warning"))
                self.assertTrue(result["analysis_flags"]["suspicious_brand_domain"])
                self.assertTrue(result["analysis_flags"]["official_domain_insertion"])
                self.assertEqual(result["reasons"].count(self.INSERTION_REASON), 1)
                self.assertTrue(result["analysis_flags"]["excessive_hostname_labels"])

    def test_similar_labels_and_unlisted_suffixes_do_not_inherit_exemptions(self):
        for host, score, inserted in (
            ("fakegoogle.com.au", 25, False), ("google-com-au.invalid", 25, False),
            ("google.comau.invalid", 25, False), ("fakeapple.com.cn", 25, False),
            ("apple-com-cn.invalid", 25, False), ("apple.comcn.invalid", 25, False),
            ("google.example", 25, False), ("apple.example", 25, False),
            # Complete shorter official domains still trigger insertion rules.
            ("google.com.aux", 35, True), ("apple.com.cnx", 35, True),
            ("google.com.cn", 35, True), ("apple.com.au", 35, True),
        ):
            with self.subTest(host=host):
                result = scanner.analyze_url("https://" + host)
                self.assertEqual(result["local_score"], score)
                self.assertTrue(result["analysis_flags"]["suspicious_brand_domain"])
                self.assertEqual(result["analysis_flags"]["official_domain_insertion"], inserted)

    def test_country_exceptions_only_remove_brand_points_and_keep_other_signals(self):
        for url in self.URLS:
            for changed, score, flag in (
                (url.replace("https:", "http:"), 30, "non_https"),
                (url.replace("https://", "https://user@"), 35, "userinfo_in_url"),
                (url + "/%3Cscript%3E", 25, "sql_xss_pattern_count"),
                (url + "/?q=union%20select", 35, "sql_xss_pattern_count"),
            ):
                with self.subTest(url=changed):
                    result = scanner.analyze_url(changed)
                    self.assert_official(result, score, "warning" if score >= 30 else "safe")
                    self.assertTrue(result["analysis_flags"][flag])
        report = {
            "enabled": True, "available": True, "lookup_status": "available",
            "source": "url_report", "stats": {"malicious": 3, "suspicious": 0},
        }
        self.vt.return_value = report
        for url in self.URLS:
            result = scanner.analyze_url(url)
            self.assert_official(result, 80, "danger")
            self.assertEqual((result["local_score"], result["vt_score_delta"]), (10, 70))
            self.assertIn(scanner.LOCAL_NO_ADDITIONAL_RISK_REASON, result["reasons"])
            self.assertIn("VirusTotal 탐지 결과 악성 3건, 의심 0건이 확인되었습니다.", result["reasons"])
            self.assertNotIn("특별한 위험 요소가 발견되지 않았습니다.", result["reasons"])
            self.assertEqual(result["reasons"], scanner.analyze_url_with_vt_result(url, report)["reasons"])

    def test_real_direct_sms_and_text_api_returns_current_flags_and_max_score(self):
        with TestClient(main.app) as client:
            for url in self.URLS:
                for path in ("/scan", "/analyze-qr"):
                    response = client.post(path, json={"url" if path == "/scan" else "content": url})
                    self.assertEqual(response.status_code, 200)
                    self.assert_official(response.json())
                for content, assumed in (
                    ("확인 " + url, False), ("확인 " + url.removeprefix("https://"), True),
                    ("SMSTO:01012345678:확인 " + url.removeprefix("https://"), True),
                    ("SMS:+821012345678?body=" + quote("확인 " + url, safe=""), False),
                ):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    parent = response.json()
                    child = parent["embedded_url_results"][0]
                    self.assert_official(child)
                    self.assertEqual(parent["final_score"], max(parent["text_score"], 10))
                    self.assertEqual(child["analysis_url"], url)
                    self.assertEqual(child["assumed_https"], assumed)
                    self.assertEqual(child["original_candidates"], [url.removeprefix("https://")] if assumed else [])

    def test_14_and_missing_cache_versions_recalculate_in_direct_and_embedded_contexts(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True):
            for url in self.URLS:
                for version in ("1.4", None):
                    for context in ("direct", "embedded"):
                        with self.subTest(url=url, version=version, context=context):
                            cached = self.old_cache(url, version=version)
                            before = copy.deepcopy(cached)
                            self.lookup.return_value = cached
                            analyzer = Mock(wraps=scanner.analyze_url)
                            result = url_cache.analyze_url_with_cache(url, analyzer=analyzer, analysis_context=context)
                            self.assert_official(result)
                            analyzer.assert_called_once_with(url)
                            self.assertEqual(result["revalidation_reason"], "ruleset_changed")
                            self.assertFalse(result["cache_hit"])
                            self.assertEqual(self.write.call_args.args[1]["ruleset_version"], RULESET_VERSION)
                            self.assertEqual(cached, before)
                            if context == "direct":
                                self.assertEqual(result["_history_event_type"], "ruleset_reclassified")
                                self.assertTrue(result["_history_should_save"])
                            else:
                                self.assertNotIn("_history_should_save", result)

    def test_current_cache_reuse_keeps_request_specific_https_metadata(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            for url in self.URLS:
                current = scanner.analyze_url(url)
                cached = make_cache_item(url, checked_at=990, **{key: current[key] for key in url_cache._CACHE_RESULT_FIELDS})
                self.lookup.return_value = cached
                self.vt.reset_mock()
                self.write.reset_mock()
                with patch.object(main, "analyze_url", side_effect=AssertionError("must reuse current cache")):
                    for content, assumed in (("확인 " + url, False), ("확인 " + url.removeprefix("https://"), True)):
                        response = client.post("/analyze-qr", json={"content": content})
                        self.assertEqual(response.status_code, 200)
                        child = response.json()["embedded_url_results"][0]
                        self.assert_official(child)
                        self.assertTrue(child["cache_hit"])
                        self.assertEqual(child["assumed_https"], assumed)
                        self.assertEqual(ASSUMED_HTTPS_REASON in child["reasons"], assumed)
                    direct = client.post("/scan", json={"url": url})
                    self.assertEqual(direct.status_code, 200)
                    self.assert_official(direct.json())
                    self.assertEqual(direct.json()["history_skip_reason"], "duplicate_unchanged")
                self.vt.assert_not_called()
                self.write.assert_not_called()
                self.assertNotIn(ASSUMED_HTTPS_REASON, cached["reasons"])

    def test_14_recalculation_failure_never_relabels_old_score_and_keeps_partial_qr(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            for url in self.URLS:
                cached = self.old_cache(url)
                before = copy.deepcopy(cached)
                self.lookup.side_effect = lambda candidate: cached if candidate == url else None
                self.write.reset_mock()
                with patch.object(main, "analyze_url", side_effect=RuntimeError("private failure")):
                    for path in ("/scan", "/analyze-qr"):
                        response = client.post(path, json={"url" if path == "/scan" else "content": url})
                        self.assertEqual(response.status_code, 503)
                        self.assertNotIn("ruleset_version", response.json())
                        self.assertNotIn("private failure", response.text)
                self.write.assert_not_called()
                def analyze(candidate):
                    if candidate == url:
                        raise RuntimeError("private failure")
                    return scanner.analyze_url(candidate)
                with patch.object(main, "analyze_url", side_effect=analyze):
                    response = client.post("/analyze-qr", json={"content": "확인 " + url.removeprefix("https://") + " https://naver.me/AbCd1234"})
                self.assertEqual(response.status_code, 200)
                parent = response.json()
                self.assertFalse(parent["embedded_url_analysis_complete"])
                self.assertEqual(parent["final_score"], max(parent["text_score"], 30))
                self.assertEqual(parent["embedded_url_results"][0]["ruleset_version"], RULESET_VERSION)
                self.assertEqual(parent["embedded_url_failures"][0]["error_code"], "EMBEDDED_URL_ANALYSIS_FAILED")
                self.assertTrue(parent["embedded_url_failures"][0]["assumed_https"])
                self.assertEqual(cached, before)

    def test_old_vt_risk_uses_new_local_score_and_preserves_historical_source(self):
        with patch.object(url_cache, "URL_CACHE_ENABLED", True), TestClient(main.app) as client:
            for url in self.URLS:
                cached = self.old_cache(url, malicious=3)
                before = copy.deepcopy(cached)
                self.lookup.return_value = cached
                for content in (url, "확인 " + url.removeprefix("https://")):
                    response = client.post("/analyze-qr", json={"content": content})
                    self.assertEqual(response.status_code, 200)
                    parent = response.json()
                    result = parent["embedded_url_results"][0] if parent["embedded_url_results"] else parent
                    self.assert_official(result, 80, "danger")
                    self.assertEqual((result["local_score"], result["vt_score_delta"]), (10, 70))
                    self.assertFalse(result["vt_available"])
                    self.assertEqual((result["vt_lookup_status"], result["vt_source"]), ("disabled", "cached_report"))
                    self.assertEqual(result["vt_malicious"], 3)
                    self.assertTrue(result["analysis_flags"]["historical_reputation_used"])
                    self.assertIn(scanner.LOCAL_NO_ADDITIONAL_RISK_REASON, result["reasons"])
                    self.assertTrue(any("재조회는 완료하지 못했습니다" in reason for reason in result["reasons"]))
                    self.assertEqual(self.write.call_args.kwargs["vt_checked_at"], 900)
                self.assertEqual(cached, before)


if __name__ == "__main__":
    unittest.main()
