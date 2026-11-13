"""Walks directories and reports lines that look like leaked secrets."""

import os
from dataclasses import dataclass
from pathlib import Path

from .ignore import IgnoreMatcher
from .patterns import ENTROPY_CANDIDATE, PATTERNS, is_high_entropy

# Directories that are almost never worth scanning.
DEFAULT_SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}
)

# Put this marker in a comment on a line to suppress findings for it.
INLINE_ALLOW = "secretguard:allow"

DEFAULT_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class Finding:
    path: Path
    line_no: int
    column: int
    rule: str
    description: str
    secret: str

    @property
    def redacted(self):
        return redact(self.secret)


def redact(secret):
    """Keep just enough of a secret to recognise it, hide the rest."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * min(len(secret) - 6, 16)}{secret[-2:]}"


def scan_text(text, path=Path("<text>"), use_entropy=True, entropy_threshold=4.5):
    """Return findings for every suspicious span in ``text``."""
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if INLINE_ALLOW in line:
            continue
        claimed = []
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                group = "secret" if "secret" in pattern.regex.groupindex else 0
                start, end = match.span(group)
                if _overlaps(claimed, start, end):
                    continue
                claimed.append((start, end))
                findings.append(
                    Finding(path, line_no, start + 1, pattern.name, pattern.description, match.group(group))
                )
        if use_entropy:
            for match in ENTROPY_CANDIDATE.finditer(line):
                start, end = match.span()
                if _overlaps(claimed, start, end):
                    continue
                if is_high_entropy(match.group(), threshold=entropy_threshold):
                    claimed.append((start, end))
                    findings.append(
                        Finding(
                            path,
                            line_no,
                            start + 1,
                            "high-entropy-string",
                            "Random-looking string that may be key material",
                            match.group(),
                        )
                    )
    findings.sort(key=lambda f: (f.line_no, f.column))
    return findings


def _overlaps(spans, start, end):
    return any(start < s_end and s_start < end for s_start, s_end in spans)


def read_text_file(path, max_bytes=DEFAULT_MAX_BYTES):
    """Return the file's text, or None if it is too large, binary or unreadable."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def iter_files(root, matcher):
    """Yield files under ``root`` that are not skipped or ignored."""
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in DEFAULT_SKIP_DIRS and not matcher.is_ignored(current / d, is_dir=True)
        )
        for name in sorted(filenames):
            path = current / name
            if not matcher.is_ignored(path):
                yield path


def scan_path(
    root,
    ignore_file=None,
    use_entropy=True,
    entropy_threshold=4.5,
    max_bytes=DEFAULT_MAX_BYTES,
):
    """Scan a file or directory tree and return all findings."""
    root = Path(root)
    matcher = IgnoreMatcher.from_file(root if root.is_dir() else root.parent, ignore_file)
    findings = []
    for path in iter_files(root, matcher):
        if path.name == ".secretignore":
            continue
        text = read_text_file(path, max_bytes)
        if text is None:
            continue
        findings.extend(scan_text(text, path, use_entropy, entropy_threshold))
    return findings
