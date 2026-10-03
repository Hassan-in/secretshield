import io, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from secret_scanner.scanner import scan_text, scan_directory
from secret_scanner.entropy import find_high_entropy_strings
import app as webapp

def real(summary):
    return [f for f in summary.findings if not f.likely_false_positive]

def test_detects_stripe_key_and_redacts_preview():
    raw = "sk_live_51H8xyzABCDEFGHIJKLMNOPQRSTUV1234567890abcd"
    s = scan_text(f'STRIPE_KEY = "{raw}"')
    f = real(s)[0]
    assert f.rule_id == "stripe_key" and f.severity == "CRITICAL"
    assert raw not in f.line_preview and raw not in f.matched_value

def test_hardcoded_password_value_masked():
    s = scan_text('password = "hunter2hunter2"')
    f = real(s)[0]
    assert "hunter2hunter2" not in f.line_preview

def test_trailing_example_comment_does_not_hide_real_secret():
    s = scan_text('api_key = "Zk3pQ9vL2mXw8RtY5uHn7BcA"  # example')
    assert real(s), "a real secret must not be hidden by an 'example' comment"

def test_placeholder_goes_to_false_positives():
    s = scan_text('api_key = "your_api_key_here_123456"')
    assert not real(s)

def test_one_finding_per_line_no_duplicates():
    s = scan_text('DB = "postgres://admin:Sup3rSecret@db.internal:5432/app"')
    assert len([f for f in s.findings if f.line_number == 1 and f.category in ("secret", "entropy")]) == 1

def test_hex_secret_caught_by_entropy():
    assert find_high_entropy_strings('secret = "9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a49"')

def test_weak_crypto_rules():
    ids = {f.rule_id for f in scan_text("h = hashlib.md5(x)\nc = AES.new(k, AES.MODE_ECB)").findings}
    assert {"weak_hash_md5", "ecb_mode"} <= ids

def test_clean_code_has_no_findings():
    s = scan_text("import secrets\ntoken = secrets.token_urlsafe(32)\n")
    assert not real(s)

def test_demo_sample_finds_critical():
    d = scan_directory(webapp.DEMO_DIR)
    assert d.counts_by_severity()["CRITICAL"] >= 3

# ---- web app ----
def client():
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()

def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, c in files.items():
            z.writestr(n, c)
    return buf.getvalue()

def test_pages_load():
    c = client()
    assert c.get("/").status_code == 200
    assert c.get("/health").json["status"] == "ok"
    assert b"Stripe" in c.get("/demo").data

def test_snippet_scan_and_api():
    c = client()
    r = c.post("/api/scan", data={"snippet": 'password = "hunter2hunter2"'})
    assert r.status_code == 200 and r.json["counts_by_severity"]["HIGH"] >= 1

def test_zip_upload_scan():
    c = client()
    z = make_zip({"app/cfg.py": 'AWS = "AKIAABCDEFGHIJKLMNOP"\n'})
    r = c.post("/api/scan", data={"archive": (io.BytesIO(z), "p.zip")}, content_type="multipart/form-data")
    assert r.status_code == 200 and r.json["counts_by_severity"]["CRITICAL"] == 1

def test_zip_slip_rejected():
    c = client()
    z = make_zip({"../../evil.py": "x=1"})
    r = c.post("/api/scan", data={"archive": (io.BytesIO(z), "p.zip")}, content_type="multipart/form-data")
    assert r.status_code == 400

def test_bad_zip_and_empty_submission_rejected():
    c = client()
    r = c.post("/api/scan", data={"archive": (io.BytesIO(b"nope"), "p.zip")}, content_type="multipart/form-data")
    assert r.status_code == 400
    assert c.post("/api/scan", data={}).status_code == 400

def test_html_report_escapes_input():
    c = client()
    r = c.post("/scan", data={"snippet": 'password = "<script>alert(1)</script>x"'})
    assert b"<script>alert(1)" not in r.data
