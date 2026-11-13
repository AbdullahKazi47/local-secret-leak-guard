import pytest

import fakes
from secretguard.patterns import is_high_entropy, shannon_entropy
from secretguard.scanner import redact, scan_text


def rules(text, **kwargs):
    return [f.rule for f in scan_text(text, **kwargs)]


@pytest.mark.parametrize(
    "line, rule",
    [
        (f'key_id = "{fakes.AWS_KEY_ID}"', "aws-access-key-id"),
        (f"aws_secret_access_key = {fakes.AWS_SECRET}", "aws-secret-access-key"),
        (f'AWS_SECRET_KEY: "{fakes.AWS_SECRET}"', "aws-secret-access-key"),
        (fakes.PEM_HEADER, "private-key-block"),
        (fakes.OPENSSH_HEADER, "private-key-block"),
        (f"Authorization: Bearer {fakes.JWT}", "jwt"),
        (f"token={fakes.GITHUB_TOKEN}", "github-token"),
        (f"slack = '{fakes.SLACK_TOKEN}'", "slack-token"),
        (f"maps_key = '{fakes.GOOGLE_KEY}'", "google-api-key"),
        (f"stripe.api = '{fakes.STRIPE_KEY}'", "stripe-live-key"),
        ('password = "correct-horse-battery"', "generic-credential-assignment"),
        ("API_KEY: 'abcd1234efgh'", "generic-credential-assignment"),
        ('client_secret="s3cr3t-value!"', "generic-credential-assignment"),
    ],
)
def test_known_patterns_are_detected(line, rule):
    assert rule in rules(line, use_entropy=False)


def test_aws_secret_reports_only_the_value():
    (finding,) = scan_text(f"aws_secret_access_key = {fakes.AWS_SECRET}", use_entropy=False)
    assert finding.secret == fakes.AWS_SECRET


@pytest.mark.parametrize(
    "line",
    [
        'DB_PASSWORD = "hunter2hunter2"',
        'config = {"password": "hunter2hunter2"}',
        "my_api_key: 'hunter2hunter2'",
    ],
)
def test_generic_assignment_handles_prefixes_and_dict_keys(line):
    (finding,) = scan_text(line, use_entropy=False)
    assert finding.rule == "generic-credential-assignment"
    assert finding.secret == "hunter2hunter2"


def test_generic_assignment_value_extraction():
    (finding,) = scan_text('password = "hunter2hunter2"', use_entropy=False)
    assert finding.secret == "hunter2hunter2"
    assert finding.column == len('password = "') + 1


@pytest.mark.parametrize(
    "line",
    [
        "password = os.environ['DB_PASSWORD']",
        'password = ""',
        'password = "short"',
        "AKIA_TOO_SHORT",
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "eyJnotreally.eyJjwt",
        "def get_api_key(self):",
    ],
)
def test_benign_lines_are_not_flagged(line):
    assert rules(line) == []


def test_line_numbers_and_columns():
    text = "first line\n\n    key = '" + fakes.AWS_KEY_ID + "'\n"
    (finding,) = scan_text(text, use_entropy=False)
    assert finding.line_no == 3
    assert finding.column == text.splitlines()[2].index("AKIA") + 1


def test_multiple_findings_on_one_line_are_sorted_by_column():
    line = f"{fakes.GITHUB_TOKEN} {fakes.AWS_KEY_ID}"
    found = scan_text(line, use_entropy=False)
    assert [f.rule for f in found] == ["github-token", "aws-access-key-id"]


def test_overlapping_matches_are_reported_once():
    # The JWT is also a long, high-entropy run; it must not be reported twice.
    found = scan_text(fakes.JWT)
    assert [f.rule for f in found] == ["jwt"]


def test_inline_allow_marker_suppresses_line():
    text = f'key = "{fakes.AWS_KEY_ID}"  # secretguard:allow\nother = "{fakes.AWS_KEY_ID}"'
    found = scan_text(text)
    assert [f.line_no for f in found] == [2]


def test_high_entropy_string_detected():
    assert rules(f'blob = "{fakes.RANDOM_TOKEN}"') == ["high-entropy-string"]


def test_high_entropy_check_can_be_disabled():
    assert rules(f'blob = "{fakes.RANDOM_TOKEN}"', use_entropy=False) == []


def test_entropy_threshold_is_configurable():
    assert rules(f'blob = "{fakes.RANDOM_TOKEN}"', entropy_threshold=6.0) == []


@pytest.mark.parametrize(
    "token",
    [
        "this_is_a_very_long_variable_name",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789012345678901234567",
        "SomeVeryLongCamelCaseClassName",
    ],
)
def test_low_entropy_or_single_class_tokens_are_ignored(token):
    assert not is_high_entropy(token)


def test_hex_strings_use_hex_threshold():
    assert is_high_entropy("3f9a1c7e5b2d8046af13ce97b05d42e8")
    assert not is_high_entropy("abababababababababababab12")


def test_shannon_entropy_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_redact_hides_most_of_the_secret():
    masked = redact(fakes.AWS_KEY_ID)
    assert masked.startswith("AKIA")
    assert fakes.AWS_KEY_ID not in masked
    assert "*" in masked
    assert redact("short") == "*****"


def test_empty_text_has_no_findings():
    assert scan_text("") == []
