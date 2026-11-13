import io
import subprocess
import sys
from pathlib import Path

import pytest

import fakes
from secretguard.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    out = io.StringIO()
    code = main([str(a) for a in args] + ["--no-color"], out=out)
    return code, out.getvalue()


def test_clean_scan_exits_zero(tmp_path):
    (tmp_path / "ok.py").write_text("print('hi')\n", encoding="utf-8")
    code, output = run(tmp_path)
    assert code == EXIT_CLEAN
    assert "No secrets found." in output


def test_findings_exit_one_and_show_location(tmp_path):
    target = tmp_path / "leak.py"
    target.write_text(f"\nKEY = '{fakes.AWS_KEY_ID}'\n", encoding="utf-8")
    code, output = run(tmp_path)
    assert code == EXIT_FINDINGS
    assert f"{target}:2:8: aws-access-key-id" in output
    assert "1 potential secret found." in output


def test_secrets_are_redacted_by_default(tmp_path):
    (tmp_path / "leak.py").write_text(fakes.AWS_KEY_ID, encoding="utf-8")
    _, output = run(tmp_path)
    assert fakes.AWS_KEY_ID not in output
    _, output = run(tmp_path, "--show-secret")
    assert fakes.AWS_KEY_ID in output


def test_missing_path_is_an_error(tmp_path, capsys):
    code, _ = run(tmp_path / "does-not-exist")
    assert code == EXIT_ERROR
    assert "path not found" in capsys.readouterr().err


def test_multiple_paths_are_combined(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.txt").write_text(fakes.PEM_HEADER, encoding="utf-8")
    code, output = run(tmp_path / "a", tmp_path / "b")
    assert code == EXIT_FINDINGS
    assert "2 potential secrets found." in output


def test_no_entropy_flag(tmp_path):
    (tmp_path / "a.py").write_text(f"x = '{fakes.RANDOM_TOKEN}'", encoding="utf-8")
    assert run(tmp_path)[0] == EXIT_FINDINGS
    assert run(tmp_path, "--no-entropy")[0] == EXIT_CLEAN


def test_ignore_file_flag(tmp_path):
    (tmp_path / "a.py").write_text(fakes.AWS_KEY_ID, encoding="utf-8")
    rules = tmp_path / "rules"
    rules.write_text("*.py\n", encoding="utf-8")
    assert run(tmp_path, "--ignore-file", rules)[0] == EXIT_CLEAN


def test_color_output_when_enabled(tmp_path):
    (tmp_path / "a.py").write_text(fakes.AWS_KEY_ID, encoding="utf-8")

    class Tty(io.StringIO):
        def isatty(self):
            return True

    out = Tty()
    main([str(tmp_path)], out=out)
    assert "\033[31m" in out.getvalue()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "secretguard" in capsys.readouterr().out


def test_runs_as_module(tmp_path):
    (tmp_path / "a.py").write_text(fakes.AWS_KEY_ID, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "secretguard", str(tmp_path), "--no-color"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == EXIT_FINDINGS
    assert "aws-access-key-id" in result.stdout


def test_project_source_contains_no_secrets():
    # The repo's own .secretignore excludes tests/; everything else must scan clean.
    code, output = run(ROOT)
    assert code == EXIT_CLEAN, output
