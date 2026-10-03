"""
app.py - web front end for SecretShield (the Round 2 deployable prototype).

Routes
  GET  /            upload / paste form
  POST /scan        scan a .zip or a pasted snippet -> HTML report
  GET  /demo        scan the bundled vulnerable sample app
  POST /api/scan    same as /scan, returns JSON
  GET  /health      liveness check for the host
"""

import io
import os
import tempfile
import zipfile

from flask import Flask, jsonify, render_template, request

from secret_scanner.report import render_html_report
from secret_scanner.scanner import scan_directory, scan_text

BASE = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.join(BASE, "test_samples", "vulnerable_app")

MAX_UPLOAD_BYTES = 5 * 1024 * 1024      # compressed upload
MAX_UNZIPPED_BYTES = 25 * 1024 * 1024   # zip-bomb guard
MAX_ZIP_FILES = 2000
MAX_SNIPPET_CHARS = 200_000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


class BadUpload(Exception):
    pass


def safe_extract(data: bytes, dest: str) -> None:
    """Extract a zip without trusting it: no path traversal, no bombs, no symlinks."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise BadUpload("That file isn't a valid .zip archive.")
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_FILES:
        raise BadUpload(f"Archive has more than {MAX_ZIP_FILES} files.")
    if sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
        raise BadUpload("Archive expands to more than 25 MB.")
    root = os.path.realpath(dest)
    for info in infos:
        if info.is_dir():
            continue
        if (info.external_attr >> 16) & 0o170000 == 0o120000:  # symlink entry
            continue
        target = os.path.realpath(os.path.join(root, info.filename))
        if not target.startswith(root + os.sep):
            raise BadUpload("Archive contains an unsafe file path.")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            out.write(src.read())


def run_scan(form, files):
    """Return (summary_dict, label) for whatever the user submitted."""
    entropy = form.get("entropy", "on") == "on"
    upload = files.get("archive")
    if upload and upload.filename:
        with tempfile.TemporaryDirectory() as tmp:
            safe_extract(upload.read(), tmp)
            summary = scan_directory(tmp, enable_entropy=entropy)
        return summary.to_dict(), upload.filename
    snippet = (form.get("snippet") or "").strip()
    if snippet:
        if len(snippet) > MAX_SNIPPET_CHARS:
            raise BadUpload("Snippet is too long (limit 200,000 characters).")
        return scan_text(snippet, enable_entropy=entropy).to_dict(), "pasted snippet"
    raise BadUpload("Upload a .zip of your project or paste some code first.")


def with_back_link(page: str) -> str:
    link = '<div style="padding:12px 32px"><a href="/" style="color:#8da2fb">&larr; Scan something else</a></div>'
    return page.replace("<main>", link + "<main>", 1)


@app.get("/")
def index():
    return render_template("index.html", error=None)


@app.post("/scan")
def scan():
    try:
        data, label = run_scan(request.form, request.files)
    except BadUpload as e:
        return render_template("index.html", error=str(e)), 400
    return with_back_link(render_html_report(data, label))


@app.get("/demo")
def demo():
    data = scan_directory(DEMO_DIR).to_dict()
    return with_back_link(render_html_report(data, "bundled demo: vulnerable_app"))


@app.post("/api/scan")
def api_scan():
    try:
        data, label = run_scan(request.form, request.files)
    except BadUpload as e:
        return jsonify(error=str(e)), 400
    data["target"] = label
    return jsonify(data)


@app.errorhandler(413)
def too_large(_):
    return render_template("index.html", error="Upload is larger than 5 MB."), 413


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
