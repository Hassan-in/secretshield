# SecretShield: Secret & Weak-Crypto Scanner

*Team ULTRON, CRYPTAURA 2.0, problem AURA-3.2: Detecting Exposed Secrets in Applications.*

**Live demo:** https://secretshield-n8hz.onrender.com/  |  **Demo video:** _paste link here_

A static analysis tool (core scanner uses only the Python standard library; the web UI uses Flask) that scans source code and project
files for **hardcoded secrets** (API keys, passwords, tokens, private keys,
connection strings) and **weak cryptographic practices** (MD5/SHA1 for
security, DES/RC4, ECB mode, hardcoded IVs/keys, disabled TLS verification,
insecure PRNGs, and more).

Built for: *Detecting Exposed Secrets in Applications* (Cryptography & Data
Protection theme).

## Why it exists

Developers routinely leak credentials into source code, config files, and Git
history — AWS keys, database passwords, Stripe/Slack/GitHub tokens, private
keys — often unintentionally. Alongside that, weak crypto choices (MD5
password hashing, ECB-mode ciphers, disabled certificate checks) quietly
undermine an app's security even when no secret is exposed. This tool catches
both classes of problems in one pass, with a redacted, shareable report.

## Features

- **25+ secret signatures**: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe,
  Twilio, SendGrid, Mailgun, npm, OpenAI, Anthropic, JWTs, PEM private keys,
  DB connection strings (Postgres/MySQL/Mongo/Redis/AMQP), generic
  `api_key=`/`password=` assignments, Basic-Auth URLs, and more.
- **14 weak-crypto checks**: MD5/SHA1 for hashing, DES/3DES/RC4, ECB mode,
  hardcoded IV/nonce, hardcoded symmetric keys, insecure PRNGs
  (`Math.random`, `random.random`), weak RSA key sizes, disabled TLS
  verification, JWT `alg:none`, low PBKDF2 iteration counts, fast hashes used
  for passwords, and suspicious home-grown crypto functions.
- **Entropy-based detection**: catches secrets that don't match any known
  vendor pattern by scoring randomness (Shannon entropy) of tokens assigned
  to key/token/secret/password-like variable names.
- **Sensitive filename detection**: flags committed `.env`, `id_rsa`, `.pem`,
  `.p12`, `credentials.json`, `.netrc`, Terraform state files, etc.
- **False-positive triage**: placeholder values (`your_api_key_here`,
  `xxxx...`, `<REDACTED>`, `example`, `changeme`, etc.) are automatically
  bucketed separately instead of cluttering the main findings list.
- **Redacted output**: matched secret values are masked (`AKIA****MPLE`)
  everywhere — console, JSON, and HTML — so reports are safe to share.
- **Previews are masked too**: the source-line preview in every report has the secret replaced, not just the value column.
- **Three output formats**: colored console summary, machine-readable JSON,
  and a polished single-file HTML dashboard.
- **CI-friendly**: `--fail-on` sets the exit code so the scanner can gate a
  build/PR pipeline.
- **Web app**: upload a `.zip` or paste code and get the report in the browser (`app.py`), with a one-click demo scan.
- **Git-history scan** (`--git-history`): finds secrets that were committed and later "deleted".
- **Hardened web upload**: zip-slip and zip-bomb protection, size limits, nothing stored after a scan.

## Run the web app

```bash
pip install -r requirements.txt
python app.py                  # http://localhost:5000
# production: gunicorn app:app
```

## Usage (CLI)

```bash
python -m secret_scanner.cli scan /path/to/project
python -m secret_scanner.cli scan . --html report.html --json report.json
python -m secret_scanner.cli scan . --git-history        # include past commits
python -m secret_scanner.cli scan . --fail-on CRITICAL   # CI gate
python -m secret_scanner.cli scan . --no-entropy
python -m secret_scanner.cli scan . --exclude legacy_vendor_code
```

### CLI options

| Flag | Description |
|---|---|
| `path` | Directory to scan (required) |
| `--html FILE` | Write an HTML report to FILE |
| `--json FILE` | Write a JSON report to FILE |
| `--no-entropy` | Disable the entropy-based generic-secret detector |
| `--git-history` | Also scan lines added in past git commits |
| `--exclude NAME` | Skip an additional directory name (repeatable) |
| `--fail-on LEVEL` | Exit 1 if a finding at or above `CRITICAL\|HIGH\|MEDIUM\|LOW` exists (default `HIGH`); use `NONE` to always exit 0 |

## Project layout

```
app.py                 # Flask web app (upload / paste / demo / JSON API)
templates/index.html   # landing page
secret_scanner/        # the scanner package
  patterns.py          # secret regex signatures + sensitive filenames
  crypto_checks.py     # weak cryptography signatures
  entropy.py           # Shannon-entropy detector (separate bar for hex)
  scanner.py           # engine: file walk, git history, dedup, redaction
  report.py            # HTML/JSON rendering
  cli.py               # command-line interface
tests/test_scanner.py  # pytest suite (scanner + web app)
test_samples/vulnerable_app/   # intentionally vulnerable demo project
Procfile, render.yaml  # deployment config
demo_report.html       # pre-generated report from the demo scan
```

Run the tests with `python -m pytest`.

## Extending it

- Add a new secret type: append a tuple to `SECRET_PATTERNS` in
  `patterns.py` — `(rule_id, name, compiled_regex, severity, description)`.
- Add a new weak-crypto check: same shape, appended to `CRYPTO_PATTERNS` in
  `crypto_checks.py`.
- Tune entropy sensitivity: adjust `min_len` / `threshold` in
  `entropy.find_high_entropy_strings`.

## Design notes & limitations

- This is a **static, regex/entropy-based** scanner — it does not execute
  code, and scans the working tree by default. Use `--git-history` to also scan
  lines added in the last 200 commits (CLI only; the web app scans uploads).
- Regex-based detection can produce occasional false positives/negatives;
  the false-positive triage step reduces noise but a human should review
  CRITICAL/HIGH findings before rotating credentials.
- Values are redacted in every report; if a finding is a true positive,
  **rotate the credential immediately** — removing it from source alone does
  not invalidate a key that may already be cached in Git history, CI logs, or
  forks.
