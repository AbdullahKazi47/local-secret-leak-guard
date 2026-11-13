import pytest

from secretguard.ignore import IgnoreMatcher, parse_rules


def matcher(tmp_path, *lines):
    return IgnoreMatcher(tmp_path, parse_rules(lines))


def test_comments_and_blank_lines_are_skipped():
    assert parse_rules(["", "   ", "# a comment", "/"]) == []


def test_unanchored_name_matches_at_any_depth(tmp_path):
    m = matcher(tmp_path, "secrets.txt")
    assert m.is_ignored(tmp_path / "secrets.txt")
    assert m.is_ignored(tmp_path / "a" / "b" / "secrets.txt")
    assert not m.is_ignored(tmp_path / "secrets.txt.bak")


def test_wildcards(tmp_path):
    m = matcher(tmp_path, "*.min.js", "fixture_?.py", "data[0-9].env")
    assert m.is_ignored(tmp_path / "web" / "app.min.js")
    assert m.is_ignored(tmp_path / "fixture_a.py")
    assert not m.is_ignored(tmp_path / "fixture_ab.py")
    assert m.is_ignored(tmp_path / "data7.env")
    assert not m.is_ignored(tmp_path / "dataX.env")


def test_negated_character_class(tmp_path):
    m = matcher(tmp_path, "log[!0-9].txt")
    assert m.is_ignored(tmp_path / "logA.txt")
    assert not m.is_ignored(tmp_path / "log1.txt")


def test_directory_rule_ignores_contents(tmp_path):
    m = matcher(tmp_path, "vendor/")
    assert m.is_ignored(tmp_path / "vendor", is_dir=True)
    assert m.is_ignored(tmp_path / "vendor" / "lib" / "x.py")
    assert m.is_ignored(tmp_path / "pkg" / "vendor" / "x.py")
    # A *file* called vendor is not a directory, so it is not ignored.
    assert not m.is_ignored(tmp_path / "vendor")


def test_anchored_path_only_matches_from_root(tmp_path):
    m = matcher(tmp_path, "tests/fixtures/*.py")
    assert m.is_ignored(tmp_path / "tests" / "fixtures" / "keys.py")
    assert not m.is_ignored(tmp_path / "src" / "tests" / "fixtures" / "keys.py")
    assert not m.is_ignored(tmp_path / "tests" / "fixtures" / "deep" / "keys.py")


def test_leading_slash_anchors_to_root(tmp_path):
    m = matcher(tmp_path, "/config.py")
    assert m.is_ignored(tmp_path / "config.py")
    assert not m.is_ignored(tmp_path / "app" / "config.py")


def test_double_star_matches_any_depth(tmp_path):
    m = matcher(tmp_path, "docs/**/*.md")
    assert m.is_ignored(tmp_path / "docs" / "a.md")
    assert m.is_ignored(tmp_path / "docs" / "x" / "y" / "a.md")
    assert not m.is_ignored(tmp_path / "other" / "a.md")


def test_negation_reincludes_file(tmp_path):
    m = matcher(tmp_path, "*.env", "!production.env")
    assert m.is_ignored(tmp_path / "local.env")
    assert not m.is_ignored(tmp_path / "production.env")


def test_last_matching_rule_wins(tmp_path):
    m = matcher(tmp_path, "!keep.txt", "*.txt")
    assert m.is_ignored(tmp_path / "keep.txt")


def test_paths_outside_root_and_root_itself_are_not_ignored(tmp_path):
    m = matcher(tmp_path / "inner", "*")
    assert not m.is_ignored(tmp_path / "elsewhere.py")
    assert not m.is_ignored(tmp_path / "inner", is_dir=True)


def test_from_file_reads_default_secretignore(tmp_path):
    (tmp_path / ".secretignore").write_text("# skip fixtures\nfixtures/\n", encoding="utf-8")
    m = IgnoreMatcher.from_file(tmp_path)
    assert m.is_ignored(tmp_path / "fixtures" / "a.py")


def test_from_file_with_explicit_path(tmp_path):
    custom = tmp_path / "custom.ignore"
    custom.write_text("*.pem\n", encoding="utf-8")
    m = IgnoreMatcher.from_file(tmp_path, custom)
    assert m.is_ignored(tmp_path / "server.pem")


def test_from_file_missing_file_ignores_nothing(tmp_path):
    m = IgnoreMatcher.from_file(tmp_path)
    assert m.rules == []
    assert not m.is_ignored(tmp_path / "anything.py")


@pytest.mark.parametrize("line", ["  *.log  ", "*.log\r"])
def test_whitespace_around_patterns_is_trimmed(tmp_path, line):
    m = matcher(tmp_path, line)
    assert m.is_ignored(tmp_path / "debug.log")
