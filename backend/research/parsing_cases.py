"""Small deterministic corpus for parser-correctness experiments."""

from research.parsing_types import ParsingCase


PARSING_CASES = (
    ParsingCase(
        case_id="control_sms_text",
        description="Plain SMS body without a URL",
        raw_qr="sms:01012345678?body=Meet%20at%207",
        expected_qr_type="sms",
        expected_body="Meet at 7",
        expected_recipient="01012345678",
    ),
    ParsingCase(
        case_id="control_mailto_subject",
        description="Plain mailto subject without a body",
        raw_qr="mailto:hello@example.com?subject=Hello",
        expected_qr_type="email",
        expected_subject="Hello",
        expected_recipient="hello@example.com",
    ),
    ParsingCase(
        case_id="control_sms_url",
        description="SMS body with an unencoded simple HTTP URL",
        raw_qr="sms:01012345678?body=https://example.com/notice",
        expected_qr_type="sms",
        expected_body="https://example.com/notice",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/notice",),
    ),
    ParsingCase(
        case_id="control_mailto_url",
        description="Mail body with an encoded simple HTTP URL",
        raw_qr=(
            "mailto:hello@example.com?"
            "body=https%3A%2F%2Fexample.com%2Fnotice"
        ),
        expected_qr_type="email",
        expected_body="https://example.com/notice",
        expected_recipient="hello@example.com",
        expected_urls=("https://example.com/notice",),
    ),
    ParsingCase(
        case_id="control_text_url",
        description="Ordinary text containing an explicit URL",
        raw_qr="Read https://example.com/notice",
        expected_qr_type="text_with_url",
        expected_urls=("https://example.com/notice",),
    ),
    ParsingCase(
        case_id="sms_encoded_ampersand",
        description="Encoded ampersand inside an SMS body URL query",
        raw_qr=(
            "sms:01012345678?body=https%3A%2F%2Fexample.com%2Fpath%3F"
            "a%3D1%26b%3D2"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1&b=2",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1&b=2",),
    ),
    ParsingCase(
        case_id="sms_encoded_question",
        description="Encoded query-start delimiter inside an SMS body URL",
        raw_qr=(
            "sms:01012345678?"
            "body=https://example.com/path%3Fa=1"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1",),
    ),
    ParsingCase(
        case_id="sms_encoded_equals",
        description="Encoded key/value delimiter inside an SMS body URL",
        raw_qr=(
            "sms:01012345678?"
            "body=https://example.com/path?a%3D1"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1",),
    ),
    ParsingCase(
        case_id="sms_encoded_fragment",
        description="Encoded fragment delimiter inside an SMS body URL",
        raw_qr=(
            "sms:01012345678?"
            "body=https://example.com/path%23section"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path#section",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path#section",),
    ),
    ParsingCase(
        case_id="sms_multiple_query_parameters",
        description="Three encoded parameters inside an SMS body URL",
        raw_qr=(
            "sms:01012345678?body=https%3A%2F%2Fexample.com%2Fpath%3F"
            "a%3D1%26b%3D2%26c%3D3"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1&b=2&c=3",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1&b=2&c=3",),
    ),
    ParsingCase(
        case_id="sms_double_encoded_query",
        description="Double-encoded SMS body URL with two parameters",
        raw_qr=(
            "sms:01012345678?body=https%253A%252F%252Fexample.com%252Fpath"
            "%253Fa%253D1%2526b%253D2"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1&b=2",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1&b=2",),
    ),
    ParsingCase(
        case_id="mailto_encoded_query",
        description="Mail body URL with encoded nested query parameters",
        raw_qr=(
            "mailto:hello@example.com?subject=Reset&"
            "body=https%3A%2F%2Fexample.com%2Freset%3F"
            "token%3Dabc%26next%3Dhome"
        ),
        expected_qr_type="email",
        expected_body="https://example.com/reset?token=abc&next=home",
        expected_subject="Reset",
        expected_recipient="hello@example.com",
        expected_urls=(
            "https://example.com/reset?token=abc&next=home",
        ),
    ),
    ParsingCase(
        case_id="smsto_encoded_query",
        description="SMSTO body URL with an encoded two-parameter query",
        raw_qr=(
            "SMSTO:01012345678:"
            "https%3A%2F%2Fexample.com%2Fpath%3Fa%3D1%26b%3D2"
        ),
        expected_qr_type="sms",
        expected_body="https://example.com/path?a=1&b=2",
        expected_recipient="01012345678",
        expected_urls=("https://example.com/path?a=1&b=2",),
    ),
    ParsingCase(
        case_id="sms_multiple_embedded_urls",
        description="Two embedded URLs with a nested query in the first URL",
        raw_qr=(
            "sms:01012345678?body=First%20https%3A%2F%2Fexample.com%2Fa%3F"
            "x%3D1%26y%3D2%20then%20https%3A%2F%2Fsecond.example%2Fb"
        ),
        expected_qr_type="sms",
        expected_body=(
            "First https://example.com/a?x=1&y=2 "
            "then https://second.example/b"
        ),
        expected_recipient="01012345678",
        expected_urls=(
            "https://example.com/a?x=1&y=2",
            "https://second.example/b",
        ),
    ),
    ParsingCase(
        case_id="sms_four_embedded_urls",
        description="Four simple URLs to separate parsing from analysis limits",
        raw_qr=(
            "sms:01012345678?body=https%3A%2F%2Fone.example%2Fa%20"
            "https%3A%2F%2Ftwo.example%2Fb%20"
            "https%3A%2F%2Fthree.example%2Fc%20"
            "https%3A%2F%2Ffour.example%2Fd"
        ),
        expected_qr_type="sms",
        expected_body=(
            "https://one.example/a https://two.example/b "
            "https://three.example/c https://four.example/d"
        ),
        expected_recipient="01012345678",
        expected_urls=(
            "https://one.example/a",
            "https://two.example/b",
            "https://three.example/c",
            "https://four.example/d",
        ),
    ),
    ParsingCase(
        case_id="control_schemeless_candidate",
        description="Ordinary text with a supported schemeless URL candidate",
        raw_qr="Visit www.example.com/path",
        expected_qr_type="text_with_url",
        expected_url_candidates=("www.example.com/path",),
    ),
)
