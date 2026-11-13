# Local Secret Leak Guard

A small, dependency-free Python CLI that scans local code directories for
accidentally hardcoded secrets — API keys, private key blocks, tokens and
passwords — before they get committed or shared. It is a defensive learning
tool: everything runs locally, nothing is sent anywhere.

## What it detects

| Rule | Example of what it catches |
| --- | --- |
| `aws-access-key-id` | `AKIA…` / `ASIA…` 20-character key IDs |
| `aws-secret-access-key` | 40-character value assigned to `aws_secret_access_key` |
| `private-key-block` | `-----BEGIN (RSA/EC/DSA/OPENSSH/PGP) PRIVATE KEY-----` |
| `jwt` | `eyJ….eyJ….…` JSON Web Tokens |
| `github-token` | `ghp_`, `gho_`, `ghs_`, `github_pat_` tokens |
| `slack-token` | `xoxb-`, `xoxp-` … tokens |
| `google-api-key` | `AIza…` keys |
| `stripe-live-key` | `sk_live_…` / `rk_live_…` keys |
| `generic-credential-assignment` | `password = "…"`, `"api_key": "…"`, `DB_PASSWORD = '…'` |
| `high-entropy-string` | long random-looking base64/hex runs (Shannon entropy check) |

Binary files, files over 1 MB, and `.git`, `node_modules`, `__pycache__`,
`.venv` directories are skipped automatically.

## Requirements

Python 3.10+ — standard library only. No installation needed.

## Usage

Run from this folder:

```
python -m secretguard                 # scan the current directory
python -m secretguard src/ config/    # scan specific paths
python -m secretguard --no-entropy    # pattern rules only
python -m secretguard --show-secret   # print matched values unredacted
```

Example output (values are redacted by default):

```
src/settings.py:12:8: aws-access-key-id - AWS access key ID [AKIA**************LE]

1 potential secret found.
```

Exit codes: `0` nothing found, `1` potential secrets found, `2` error
(e.g. path does not exist) — handy for a pre-commit hook or CI step.

Other options: `--ignore-file PATH`, `--entropy-threshold BITS` (default 4.5),
`--max-bytes N`, `--no-color`, `--version`. See `python -m secretguard -h`.

### Ignoring paths: `.secretignore`

Put a `.secretignore` in the directory you scan (or pass `--ignore-file`).
It uses a subset of `.gitignore` syntax:

```
# Trailing slash: directories only, at any depth
third_party/
# No slash: matches the name at any depth
*.min.js
# Contains a slash: relative to the scan root
tests/fixtures/*.py
# ** spans any number of directories
docs/**/*.md
# ! re-includes something excluded above
!docs/keep.md
```

Comments must be on their own line. As in `.gitignore`, a file inside an
ignored directory cannot be re-included.

### Suppressing a single line

Add `secretguard:allow` anywhere on the line, for example in a comment:

```python
EXAMPLE_KEY = "..."  # secretguard:allow
```

## Running the tests

```
python -m pytest -q
```

The suite covers each pattern, false-positive cases, entropy scoring,
`.secretignore` semantics, file-handling edge cases (binary, large,
non-UTF-8, CRLF, empty files) and the CLI. Fake credentials used by the
tests are assembled at runtime in `tests/fakes.py`, and this repo's own
`.secretignore` excludes `tests/`, so the tool scans its own source clean.

## Limitations

Regex and entropy heuristics produce both false positives (e.g. hashes in
lock files) and false negatives (secrets split across lines or encoded).
Treat results as leads to review, not a guarantee. If a real secret was
ever committed, rotate it — deleting it from the file is not enough.

Built with Claude Code, picked by VERONICA.
