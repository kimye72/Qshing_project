import unittest

from app.constants import MAX_EMBEDDED_URLS_ANALYZED
from research.compare_parsers import compare_result, run_comparison
from research.parsing_baseline import parse_baseline
from research.parsing_cases import PARSING_CASES
from research.parsing_proposed import parse_proposed


CASES_BY_ID = {case.case_id: case for case in PARSING_CASES}


class ParserComparisonTests(unittest.TestCase):
    def _assert_proposed_exact(self, case_id: str) -> None:
        case = CASES_BY_ID[case_id]
        comparison = compare_result(case, parse_proposed(case.raw_qr))
        self.assertTrue(comparison.exact_success, case_id)

    def test_case_ids_are_unique(self):
        self.assertEqual(len(CASES_BY_ID), len(PARSING_CASES))

    def test_both_parsers_handle_simple_controls(self):
        for case_id in (
            "control_sms_text",
            "control_mailto_subject",
            "control_sms_url",
            "control_mailto_url",
            "control_text_url",
            "control_schemeless_candidate",
        ):
            with self.subTest(case_id=case_id):
                case = CASES_BY_ID[case_id]
                self.assertTrue(
                    compare_result(
                        case,
                        parse_baseline(case.raw_qr),
                    ).exact_success
                )
                self.assertTrue(
                    compare_result(
                        case,
                        parse_proposed(case.raw_qr),
                    ).exact_success
                )

    def test_proposed_preserves_encoded_delimiters(self):
        for case_id in (
            "sms_encoded_ampersand",
            "sms_encoded_question",
            "sms_encoded_equals",
            "sms_encoded_fragment",
        ):
            with self.subTest(case_id=case_id):
                self._assert_proposed_exact(case_id)

    def test_proposed_handles_sms_mailto_and_smsto_queries(self):
        for case_id in (
            "sms_multiple_query_parameters",
            "mailto_encoded_query",
            "smsto_encoded_query",
        ):
            with self.subTest(case_id=case_id):
                self._assert_proposed_exact(case_id)

    def test_proposed_handles_supported_double_encoding(self):
        self._assert_proposed_exact("sms_double_encoded_query")

    def test_proposed_preserves_multiple_urls_in_order(self):
        case = CASES_BY_ID["sms_multiple_embedded_urls"]
        result = parse_proposed(case.raw_qr)
        self.assertEqual(result.extracted_urls, case.expected_urls)
        self.assertTrue(compare_result(case, result).exact_success)

    def test_parser_output_is_not_truncated_by_analysis_limit(self):
        case = CASES_BY_ID["sms_four_embedded_urls"]
        self.assertGreater(len(case.expected_urls), MAX_EMBEDDED_URLS_ANALYZED)
        for parser in (parse_baseline, parse_proposed):
            with self.subTest(parser=parser.__name__):
                result = parser(case.raw_qr)
                self.assertEqual(result.extracted_urls, case.expected_urls)
                self.assertTrue(compare_result(case, result).exact_success)

    def test_baseline_reproduces_decode_first_boundary_failures(self):
        for case_id in (
            "sms_encoded_ampersand",
            "sms_encoded_fragment",
            "sms_multiple_query_parameters",
            "sms_double_encoded_query",
            "mailto_encoded_query",
            "smsto_encoded_query",
            "sms_multiple_embedded_urls",
        ):
            with self.subTest(case_id=case_id):
                case = CASES_BY_ID[case_id]
                self.assertFalse(
                    compare_result(
                        case,
                        parse_baseline(case.raw_qr),
                    ).exact_success
                )

    def test_comparison_summary_is_deterministic(self):
        first = run_comparison()
        second = run_comparison()
        self.assertEqual(first["total"], len(PARSING_CASES))
        self.assertEqual(first["baseline_parse_success"], 16)
        self.assertEqual(first["proposed_parse_success"], 16)
        self.assertEqual(first["baseline_exact_success"], 9)
        self.assertEqual(first["proposed_exact_success"], 16)
        self.assertEqual(
            first["baseline_failures"],
            [
                "sms_encoded_ampersand",
                "sms_encoded_fragment",
                "sms_multiple_query_parameters",
                "sms_double_encoded_query",
                "mailto_encoded_query",
                "smsto_encoded_query",
                "sms_multiple_embedded_urls",
            ],
        )
        self.assertEqual(first["proposed_failures"], [])
        self.assertEqual(
            first["baseline_exact_success"],
            second["baseline_exact_success"],
        )
        self.assertEqual(
            first["proposed_exact_success"],
            second["proposed_exact_success"],
        )
        self.assertEqual(
            first["baseline_failures"],
            second["baseline_failures"],
        )
        self.assertEqual(
            first["proposed_failures"],
            second["proposed_failures"],
        )


if __name__ == "__main__":
    unittest.main()
