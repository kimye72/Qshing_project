"""Run the deterministic baseline-versus-proposed parser comparison."""

from urllib.parse import urlsplit

from research.parsing_baseline import parse_baseline
from research.parsing_cases import PARSING_CASES
from research.parsing_proposed import parse_proposed
from research.parsing_types import ComparisonResult, ParserResult, ParsingCase


def _url_structures(urls: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    return tuple((urlsplit(url).query, urlsplit(url).fragment) for url in urls)


def compare_result(
    case: ParsingCase,
    result: ParserResult,
) -> ComparisonResult:
    qr_type_match = result.qr_type == case.expected_qr_type
    body_match = result.body == case.expected_body
    subject_match = result.subject == case.expected_subject
    recipient_match = result.recipient == case.expected_recipient
    urls_match = result.extracted_urls == case.expected_urls
    url_count_match = len(result.extracted_urls) == len(case.expected_urls)
    query_preserved = (
        url_count_match
        and _url_structures(result.extracted_urls)
        == _url_structures(case.expected_urls)
    )
    candidates_match = (
        result.extracted_url_candidates
        == case.expected_url_candidates
    )
    exact_success = all(
        (
            result.parse_success,
            qr_type_match,
            body_match,
            subject_match,
            recipient_match,
            urls_match,
            url_count_match,
            query_preserved,
            candidates_match,
        )
    )
    return ComparisonResult(
        parse_success=result.parse_success,
        qr_type_exact_match=qr_type_match,
        body_exact_match=body_match,
        subject_exact_match=subject_match,
        recipient_exact_match=recipient_match,
        extracted_url_exact_match=urls_match,
        expected_url_count=len(case.expected_urls),
        actual_url_count=len(result.extracted_urls),
        url_count_match=url_count_match,
        url_query_preservation=query_preserved,
        url_candidate_exact_match=candidates_match,
        exact_success=exact_success,
    )


def run_comparison() -> dict:
    rows: list[dict] = []
    baseline_failures: list[str] = []
    proposed_failures: list[str] = []
    baseline_parse_success = 0
    proposed_parse_success = 0

    for case in PARSING_CASES:
        baseline = parse_baseline(case.raw_qr)
        proposed = parse_proposed(case.raw_qr)
        baseline_comparison = compare_result(case, baseline)
        proposed_comparison = compare_result(case, proposed)
        baseline_parse_success += int(baseline.parse_success)
        proposed_parse_success += int(proposed.parse_success)
        if not baseline_comparison.exact_success:
            baseline_failures.append(case.case_id)
        if not proposed_comparison.exact_success:
            proposed_failures.append(case.case_id)
        rows.append(
            {
                "case": case,
                "baseline": baseline,
                "proposed": proposed,
                "baseline_comparison": baseline_comparison,
                "proposed_comparison": proposed_comparison,
            }
        )

    total = len(PARSING_CASES)
    return {
        "rows": rows,
        "total": total,
        "baseline_exact_success": total - len(baseline_failures),
        "proposed_exact_success": total - len(proposed_failures),
        "baseline_parse_success": baseline_parse_success,
        "proposed_parse_success": proposed_parse_success,
        "baseline_failures": baseline_failures,
        "proposed_failures": proposed_failures,
    }


def main() -> None:
    comparison = run_comparison()
    for row in comparison["rows"]:
        case = row["case"]
        print(f"Case ID: {case.case_id}")
        print(f"Description: {case.description}")
        print(
            "Expected:",
            {
                "qr_type": case.expected_qr_type,
                "body": case.expected_body,
                "subject": case.expected_subject,
                "recipient": case.expected_recipient,
                "extracted_urls": list(case.expected_urls),
                "extracted_url_candidates": list(
                    case.expected_url_candidates
                ),
            },
        )
        print("Baseline result:", row["baseline"].to_dict())
        print("Proposed result:", row["proposed"].to_dict())
        print(
            "Baseline success:",
            row["baseline_comparison"].exact_success,
        )
        print(
            "Proposed success:",
            row["proposed_comparison"].exact_success,
        )
        print()

    print(f"Total cases: {comparison['total']}")
    print(
        "Baseline parse success: "
        f"{comparison['baseline_parse_success']}/{comparison['total']}"
    )
    print(
        "Proposed parse success: "
        f"{comparison['proposed_parse_success']}/{comparison['total']}"
    )
    print(
        "Baseline exact success: "
        f"{comparison['baseline_exact_success']}/{comparison['total']}"
    )
    print(
        "Proposed exact success: "
        f"{comparison['proposed_exact_success']}/{comparison['total']}"
    )
    print("Baseline failures:")
    for case_id in comparison["baseline_failures"]:
        print(f"- {case_id}")
    print("Proposed failures:")
    if comparison["proposed_failures"]:
        for case_id in comparison["proposed_failures"]:
            print(f"- {case_id}")
    else:
        print("- none")


if __name__ == "__main__":
    main()
