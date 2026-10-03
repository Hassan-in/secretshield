"""
patterns.py
Library of regex signatures for known credential / secret formats.
Each entry: (name, compiled_regex, severity, description)
Severity: CRITICAL, HIGH, MEDIUM, LOW
"""

import re

# Each tuple: (id, human name, regex, severity, description)
SECRET_PATTERNS = [
    (
        "aws_access_key",
        "AWS Access Key ID",
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "CRITICAL",
        "Amazon Web Services access key identifier.",
    ),
    (
        "aws_secret_key",
        "AWS Secret Access Key",
        re.compile(r"(?i)aws(.{0,20})?(secret|access)?[_-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"),
        "CRITICAL",
        "Amazon Web Services secret access key.",
    ),
    (
        "google_api_key",
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "HIGH",
        "Google Cloud / Firebase / Maps API key.",
    ),
    (
        "gcp_service_account",
        "GCP Service Account Private Key Block",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "CRITICAL",
        "Embedded Google Cloud service-account JSON credential.",
    ),
    (
        "github_token",
        "GitHub Token",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b"),
        "CRITICAL",
        "GitHub personal access / OAuth / app token.",
    ),
    (
        "gitlab_token",
        "GitLab Token",
        re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b"),
        "CRITICAL",
        "GitLab personal access token.",
    ),
    (
        "slack_token",
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
        "HIGH",
        "Slack bot/user/app OAuth token.",
    ),
    (
        "slack_webhook",
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,50}"),
        "MEDIUM",
        "Slack incoming webhook URL (allows posting as the app).",
    ),
    (
        "stripe_key",
        "Stripe API Key",
        re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,247}\b"),
        "CRITICAL",
        "Stripe secret or restricted API key.",
    ),
    (
        "twilio_key",
        "Twilio API Key/SID",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b|\bAC[0-9a-fA-F]{32}\b"),
        "HIGH",
        "Twilio API key or account SID.",
    ),
    (
        "sendgrid_key",
        "SendGrid API Key",
        re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
        "HIGH",
        "SendGrid API key.",
    ),
    (
        "mailgun_key",
        "Mailgun API Key",
        re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        "MEDIUM",
        "Mailgun API key.",
    ),
    (
        "npm_token",
        "NPM Access Token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "HIGH",
        "NPM publish/automation token.",
    ),
    (
        "openai_key",
        "OpenAI API Key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,48}(T3BlbkFJ[A-Za-z0-9]{20,48})?\b"),
        "HIGH",
        "OpenAI API secret key.",
    ),
    (
        "anthropic_key",
        "Anthropic API Key",
        re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,120}\b"),
        "HIGH",
        "Anthropic API secret key.",
    ),
    (
        "jwt_token",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "MEDIUM",
        "Hardcoded JWT (may embed session or identity data).",
    ),
    (
        "private_key_block",
        "Private Key Block",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "CRITICAL",
        "PEM-encoded private key committed to the repository.",
    ),
    (
        "generic_api_key_assignment",
        "Generic API Key/Secret Assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=]{16,})[\"']"
        ),
        "HIGH",
        "Variable name suggests an API key/secret hardcoded as a literal.",
    ),
    (
        "hardcoded_password",
        "Hardcoded Password",
        re.compile(
            r"(?i)\b(password|passwd|pwd|db[_-]?pass)\b\s*[:=]\s*[\"']([^\"'\s]{4,})[\"']"
        ),
        "HIGH",
        "Password literal assigned directly in source/config.",
    ),
    (
        "db_connection_string",
        "Database Connection String w/ Credentials",
        re.compile(
            r"(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:\s\"']+:[^@\s\"']+@[^\s\"']+"
        ),
        "CRITICAL",
        "Connection URI with embedded username/password.",
    ),
    (
        "azure_storage_key",
        "Azure Storage Account Key",
        re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{60,}"),
        "CRITICAL",
        "Azure Storage account access key.",
    ),
    (
        "heroku_api_key",
        "Heroku API Key",
        re.compile(r"(?i)heroku(.{0,20})?[\"']?\s*[:=]\s*[\"']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        "MEDIUM",
        "Heroku API key (UUID format).",
    ),
    (
        "firebase_url",
        "Firebase Database URL",
        re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
        "LOW",
        "Firebase realtime database URL — verify security rules are set.",
    ),
    (
        "ssh_priv_env",
        "SSH Key Assigned to Variable",
        re.compile(r"(?i)ssh[_-]?priv(ate)?[_-]?key\s*[:=]"),
        "MEDIUM",
        "Variable name suggests an SSH private key is hardcoded nearby.",
    ),
    (
        "basic_auth_url",
        "Credentials in URL (Basic Auth)",
        re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@\"']+:[^/\s:@\"']+@[^\s\"']+"),
        "HIGH",
        "URL containing inline username:password.",
    ),
]

# File names / extensions that are worth flagging just for existing in a repo
SENSITIVE_FILENAMES = [
    (re.compile(r"(^|/)\.env(\..+)?$"), "MEDIUM", ".env file committed to repository."),
    (re.compile(r"(^|/)id_rsa$"), "CRITICAL", "SSH private key file committed."),
    (re.compile(r"(^|/)id_dsa$"), "CRITICAL", "SSH private key file committed."),
    (re.compile(r"\.pem$"), "CRITICAL", "PEM certificate/key file committed."),
    (re.compile(r"\.pfx$|\.p12$"), "CRITICAL", "PKCS#12 keystore committed."),
    (re.compile(r"(^|/)credentials\.json$"), "CRITICAL", "Cloud provider credentials file committed."),
    (re.compile(r"(^|/)\.npmrc$"), "MEDIUM", "npm config file may contain auth tokens."),
    (re.compile(r"(^|/)\.netrc$"), "HIGH", "netrc file stores plaintext login credentials."),
    (re.compile(r"(^|/)terraform\.tfstate$"), "HIGH", "Terraform state file may contain plaintext secrets."),
]

# Directories/paths that should generally be skipped during a scan
DEFAULT_EXCLUDES = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "vendor", "target", ".idea", ".vscode",
}

# File extensions unlikely to contain useful text (skip for performance)
BINARY_EXT_SKIP = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mov", ".exe", ".dll", ".so",
    ".class", ".jar", ".pyc", ".bin",
}
