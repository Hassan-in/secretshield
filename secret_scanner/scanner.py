"""
scanner.py
Core engine: walks a directory tree, applies secret-pattern, weak-crypto,
and entropy detectors line by line, and produces structured findings.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .patterns import SECRET_PATTERNS, SENSITIVE_FILENAMES, DEFAULT_EXCLUDES, BINARY_EXT_SKIP
from .crypto_checks import CRYPTO_PATTERNS
from .entropy import find_high_entropy_strings

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Placeholder markers. Checked against the MATCHED VALUE only (never the whole
# line), so a trailing "# example" comment cannot hide a real secret.
PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|placeholder|dummy|fake|changeme|redacted|your[_-]?(api[_-]?)?(key|token|secret)|x{4,}|<[^>]+>)"
)
VALUE_GROUP_RULES = {"generic_api_key_assignment", "hardcoded_password", "aws_secret_key"}
MAX_FILE_BYTES = 1_000_000  # skip files larger than ~1 MB


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    category: str          # "secret" | "crypto" | "entropy" | "filename"
    description: str
    file: str
    line_number: int
    line_preview: str
    matched_value: str      # redacted before display
    likely_false_positive: bool = False
    commit: str = ""        # set only for git-history findings


@dataclass
class ScanSummary:
    files_scanned: int = 0
    files_skipped: int = 0
    findings: List[Finding] = field(default_factory=list)

    def counts_by_severity(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if not f.likely_false_positive:
                counts[f.severity] += 1
        return counts

    def to_dict(self):
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "counts_by_severity": self.counts_by_severity(),
            "findings": [asdict(f) for f in self.findings],
        }


def _redact(value: str, keep: int = 4) -> str:
    """Mask a secret value for safe display in reports."""
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


def _is_probable_false_positive(line: str, matched: str) -> bool:
    if PLACEHOLDER_RE.search(matched):
        return True
    # low-diversity strings like "0000000000" or "aaaaaaaaaa"
    if len(set(matched)) <= 2 and len(matched) > 6:
        return True
    return False


def _safe_preview(line: str, secrets) -> str:
    """Line preview with every detected secret value masked."""
    preview = line.strip()
    for raw in sorted({r for r in secrets if r}, key=len, reverse=True):
        preview = preview.replace(raw.strip(), _redact(raw))
    return preview[:200]


def _should_skip_dir(dirname: str, extra_excludes: Optional[set]) -> bool:
    excludes = DEFAULT_EXCLUDES | (extra_excludes or set())
    return dirname in excludes or dirname.startswith(".git")


def _iter_files(root: str, extra_excludes: Optional[set], follow_hidden: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if not _should_skip_dir(d, extra_excludes) and (follow_hidden or not d.startswith("."))
        ]
        for fname in filenames:
            if not follow_hidden and fname.startswith(".") and fname not in (".env",):
                # still allow .env since it's a classic secret-leak target
                if fname != ".env":
                    continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in BINARY_EXT_SKIP:
                continue
            yield os.path.join(dirpath, fname)


def scan_line(rel_path, lineno, line, findings, enable_entropy=True, commit=""):
    """Apply every detector to one line and append Findings."""
    if len(line) > 2000:  # minified/bundled line - noisy and slow
        return
    loc = f"{rel_path}@{commit[:8]}" if commit else rel_path
    hits = []  # (rule_id, name, severity, category, desc, raw_value, fp)

    for rule_id, name, regex, severity, desc in SECRET_PATTERNS:
        for m in regex.finditer(line):
            raw = m.group(m.lastindex) if (rule_id in VALUE_GROUP_RULES and m.lastindex) else m.group(0)
            hits.append((rule_id, name, severity, "secret", desc, raw,
                         _is_probable_false_positive(line, raw)))

    if enable_entropy:
        for token, ent in find_high_entropy_strings(line):
            hits.append(("high_entropy_string",
                         "High-Entropy String in Credential-like Assignment", "MEDIUM", "entropy",
                         f"Randomness score {ent} bits/char in a key/token/secret-like assignment.",
                         token, _is_probable_false_positive(line, token)))

    # One finding per line for secret/entropy hits: keep the real, most severe one
    if hits:
        hits.sort(key=lambda h: (h[6], SEVERITY_ORDER.get(h[2], 9)))
        best = hits[0]
        preview = _safe_preview(line, [h[5] for h in hits])
        findings.append(Finding(best[0], best[1], best[2], best[3], best[4], loc, lineno,
                                preview, _redact(best[5]), best[6], commit))

    for rule_id, name, regex, severity, desc in CRYPTO_PATTERNS:
        if regex.search(line):
            findings.append(Finding(rule_id, name, severity, "crypto", desc, loc, lineno,
                                    _safe_preview(line, []), "", False, commit))


def scan_file_content(filepath, rel_path, text, findings, enable_entropy=True):
    for regex, severity, desc in SENSITIVE_FILENAMES:
        if regex.search(rel_path.replace(os.sep, "/")):
            findings.append(Finding(
                rule_id="sensitive_filename", name="Sensitive File Present", severity=severity,
                category="filename", description=desc, file=rel_path, line_number=0,
                line_preview=os.path.basename(rel_path), matched_value=os.path.basename(rel_path),
            ))
    for lineno, line in enumerate(text.splitlines(), start=1):
        scan_line(rel_path, lineno, line, findings, enable_entropy)


def _sort(summary):
    summary.findings.sort(key=lambda f: (f.likely_false_positive, SEVERITY_ORDER.get(f.severity, 9),
                                         f.file, f.line_number))
    return summary


def scan_text(text: str, name: str = "pasted_snippet.py", enable_entropy: bool = True) -> ScanSummary:
    """Scan a single pasted snippet (used by the web UI)."""
    summary = ScanSummary(files_scanned=1)
    scan_file_content(name, name, text[:MAX_FILE_BYTES], summary.findings, enable_entropy)
    return _sort(summary)


def scan_git_history(repo: str, max_commits: int = 200, enable_entropy: bool = True) -> ScanSummary:
    """Scan lines ADDED in past commits - finds secrets that were committed then 'deleted'."""
    summary = ScanSummary()
    try:
        out = subprocess.run(
            ["git", "-C", repo, "log", "-p", "--all", "--no-color", "-U0", f"--max-count={max_commits}",
             "--pretty=format:@@COMMIT %H"],
            capture_output=True, text=True, errors="ignore", timeout=120, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return summary
    commit, path, lineno, seen = "", "", 0, set()
    for line in out.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line.split()[1]; summary.files_scanned += 1
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            tmp = []
            scan_line(path, lineno, line[1:], tmp, enable_entropy, commit)
            for f in tmp:
                key = (f.rule_id, f.file.split("@")[0], f.matched_value or f.line_preview)
                if key not in seen:   # same secret re-added in many commits: report once
                    seen.add(key); summary.findings.append(f)
            lineno += 1
    return _sort(summary)


def scan_directory(root: str, extra_excludes: Optional[set] = None,
                    enable_entropy: bool = True, follow_hidden: bool = True) -> ScanSummary:
    summary = ScanSummary()
    root = os.path.abspath(root)

    for filepath in _iter_files(root, extra_excludes, follow_hidden):
        rel_path = os.path.relpath(filepath, root)
        try:
            if os.path.getsize(filepath) > MAX_FILE_BYTES:
                summary.files_skipped += 1
                continue
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except (OSError, IsADirectoryError):
            summary.files_skipped += 1
            continue

        summary.files_scanned += 1
        scan_file_content(filepath, rel_path, text, summary.findings, enable_entropy=enable_entropy)

    return _sort(summary)
