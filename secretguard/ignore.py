"""Parsing and matching for .secretignore files.

Syntax (a small subset of .gitignore):

* Blank lines and lines starting with ``#`` are skipped.
* ``name`` (no slash) matches any file or directory with that name,
  at any depth. Shell wildcards (``*``, ``?``, ``[abc]``) are allowed.
* ``dir/`` (trailing slash) matches only directories.
* ``path/to/file`` (contains a slash) matches relative to the scan root.
* ``**`` inside a path pattern matches any number of directories.
* ``!pattern`` re-includes something an earlier pattern excluded.
"""

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

IGNORE_FILENAME = ".secretignore"


@dataclass(frozen=True)
class IgnoreRule:
    regex: re.Pattern
    anchored: bool
    dir_only: bool
    negate: bool


def _compile(pattern):
    """Translate a glob into a regex where ``*`` does not cross ``/``."""
    parts = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        elif pattern[i] == "[":
            end = pattern.find("]", i + 2)
            if end == -1:
                parts.append(re.escape(pattern[i]))
                i += 1
            else:
                body = pattern[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                parts.append("[" + body.replace("\\", "\\\\") + "]")
                i = end + 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(parts) + r"\Z")


def parse_rules(lines):
    rules = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        if negate:
            line = line[1:]
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        anchored = "/" in line
        line = line.lstrip("/")
        if not line:
            continue
        rules.append(IgnoreRule(_compile(line), anchored, dir_only, negate))
    return rules


class IgnoreMatcher:
    """Decides whether a path below ``root`` should be skipped."""

    def __init__(self, root, rules=()):
        self.root = Path(root)
        self.rules = list(rules)

    @classmethod
    def from_file(cls, root, ignore_file=None):
        """Load rules from ``ignore_file`` or ``<root>/.secretignore``."""
        path = Path(ignore_file) if ignore_file else Path(root) / IGNORE_FILENAME
        if not path.is_file():
            return cls(root)
        text = path.read_text(encoding="utf-8", errors="replace")
        return cls(root, parse_rules(text.splitlines()))

    def is_ignored(self, path, is_dir=False):
        """Return True if ``path`` or any of its parent directories is ignored."""
        try:
            rel = PurePosixPath(Path(path).relative_to(self.root).as_posix())
        except ValueError:
            return False
        if str(rel) == ".":
            return False
        for parent in reversed(rel.parents[:-1]):
            if self._matches(parent, is_dir=True):
                return True
        return self._matches(rel, is_dir)

    def _matches(self, rel, is_dir):
        ignored = False
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            target = str(rel) if rule.anchored else rel.name
            if rule.regex.match(target):
                ignored = not rule.negate
        return ignored
