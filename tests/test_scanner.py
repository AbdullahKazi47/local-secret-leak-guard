import fakes
from secretguard.scanner import read_text_file, scan_path


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_scans_directories_recursively(tmp_path):
    write(tmp_path / "a.py", f'KEY = "{fakes.AWS_KEY_ID}"\n')
    write(tmp_path / "pkg" / "deep" / "b.cfg", f"{fakes.PEM_HEADER}\n")
    found = scan_path(tmp_path)
    assert {(f.path.name, f.rule) for f in found} == {
        ("a.py", "aws-access-key-id"),
        ("b.cfg", "private-key-block"),
    }


def test_clean_directory_has_no_findings(tmp_path):
    write(tmp_path / "app.py", "def main():\n    return 42\n")
    assert scan_path(tmp_path) == []


def test_reports_correct_path_and_line(tmp_path):
    target = write(tmp_path / "src" / "settings.py", f"DEBUG = True\nTOKEN = '{fakes.GITHUB_TOKEN}'\n")
    (finding,) = scan_path(tmp_path)
    assert finding.path == target
    assert finding.line_no == 2


def test_scanning_a_single_file(tmp_path):
    target = write(tmp_path / "one.txt", fakes.JWT)
    (finding,) = scan_path(target)
    assert finding.rule == "jwt"


def test_secretignore_skips_paths(tmp_path):
    write(tmp_path / ".secretignore", "tests/fixtures/\nthird_party/\n*.lock\n")
    write(tmp_path / "tests" / "fixtures" / "keys.py", f"{fakes.AWS_KEY_ID}\n")
    write(tmp_path / "third_party" / "lib.js", f"{fakes.STRIPE_KEY}\n")
    write(tmp_path / "deps.lock", f"{fakes.SLACK_TOKEN}\n")
    write(tmp_path / "real.py", f"{fakes.GOOGLE_KEY}\n")
    found = scan_path(tmp_path)
    assert [f.path.name for f in found] == ["real.py"]


def test_explicit_ignore_file_overrides_default(tmp_path):
    write(tmp_path / ".secretignore", "*.py\n")
    custom = write(tmp_path / "elsewhere" / "rules.txt", "*.cfg\n")
    write(tmp_path / "a.py", f"{fakes.AWS_KEY_ID}\n")
    write(tmp_path / "b.cfg", f"{fakes.AWS_KEY_ID}\n")
    found = scan_path(tmp_path, ignore_file=custom)
    assert [f.path.name for f in found] == ["a.py"]


def test_secretignore_file_itself_is_not_scanned(tmp_path):
    write(tmp_path / ".secretignore", f"# old key was {fakes.AWS_KEY_ID}\n")
    assert scan_path(tmp_path) == []


def test_default_skip_dirs(tmp_path):
    write(tmp_path / ".git" / "config", f"{fakes.AWS_KEY_ID}\n")
    write(tmp_path / "node_modules" / "x" / "index.js", f"{fakes.AWS_KEY_ID}\n")
    write(tmp_path / "__pycache__" / "m.txt", f"{fakes.AWS_KEY_ID}\n")
    assert scan_path(tmp_path) == []


def test_binary_files_are_skipped(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + fakes.AWS_KEY_ID.encode())
    assert scan_path(tmp_path) == []


def test_large_files_are_skipped(tmp_path):
    write(tmp_path / "big.txt", fakes.AWS_KEY_ID + "\n" + "x" * 500)
    assert scan_path(tmp_path, max_bytes=100) == []
    assert len(scan_path(tmp_path, max_bytes=10_000)) == 1


def test_non_utf8_text_is_still_scanned(tmp_path):
    (tmp_path / "latin1.txt").write_bytes("caf\xe9 ".encode("latin-1") + fakes.AWS_KEY_ID.encode())
    (finding,) = scan_path(tmp_path)
    assert finding.rule == "aws-access-key-id"


def test_empty_files_are_fine(tmp_path):
    write(tmp_path / "empty.py", "")
    assert scan_path(tmp_path) == []


def test_crlf_line_endings_keep_line_numbers(tmp_path):
    (tmp_path / "win.txt").write_bytes(b"one\r\ntwo\r\n" + fakes.AWS_KEY_ID.encode() + b"\r\n")
    (finding,) = scan_path(tmp_path)
    assert finding.line_no == 3


def test_read_text_file_missing_returns_none(tmp_path):
    assert read_text_file(tmp_path / "nope.txt") is None


def test_entropy_option_is_passed_through(tmp_path):
    write(tmp_path / "a.py", f'blob = "{fakes.RANDOM_TOKEN}"\n')
    assert len(scan_path(tmp_path)) == 1
    assert scan_path(tmp_path, use_entropy=False) == []
