"""
report.py
Renders a ScanSummary into a single self-contained HTML report.
"""

import html
import json
from datetime import datetime

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
}

CATEGORY_LABELS = {
    "secret": "Exposed Secret",
    "crypto": "Weak Cryptography",
    "entropy": "High-Entropy Token",
    "filename": "Sensitive File",
}


def _esc(s):
    return html.escape(str(s), quote=True)


def render_html_report(summary_dict: dict, scanned_path: str) -> str:
    counts = summary_dict["counts_by_severity"]
    findings = summary_dict["findings"]
    real_findings = [f for f in findings if not f["likely_false_positive"]]
    fp_findings = [f for f in findings if f["likely_false_positive"]]

    total = sum(counts.values())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def severity_badge(sev):
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55">{sev}</span>'

    def render_row(f):
        cat_label = CATEGORY_LABELS.get(f["category"], f["category"])
        val = f'<code class="mono">{_esc(f["matched_value"])}</code>' if f["matched_value"] else "&mdash;"
        return f"""
        <tr>
          <td>{severity_badge(f['severity'])}</td>
          <td>{_esc(cat_label)}</td>
          <td class="mono">{_esc(f['file'])}{':' + str(f['line_number']) if f['line_number'] else ''}</td>
          <td>{_esc(f['name'])}</td>
          <td>{val}</td>
          <td class="desc">{_esc(f['description'])}<div class="preview mono">{_esc(f['line_preview'])}</div></td>
        </tr>"""

    rows_html = "\n".join(render_row(f) for f in real_findings) or (
        '<tr><td colspan="6" class="empty">No issues detected. Nice and clean.</td></tr>'
    )
    fp_rows_html = "\n".join(render_row(f) for f in fp_findings)

    fp_section = ""
    if fp_findings:
        fp_section = f"""
        <details class="fp-details">
          <summary>{len(fp_findings)} likely false positive(s) (placeholders/examples) — click to expand</summary>
          <table>
            <thead><tr><th>Severity</th><th>Category</th><th>Location</th><th>Rule</th><th>Value</th><th>Details</th></tr></thead>
            <tbody>{fp_rows_html}</tbody>
          </table>
        </details>
        """

    stat_cards = "".join(
        f"""<div class="stat-card" style="border-top:4px solid {SEVERITY_COLORS[sev]}">
              <div class="stat-num" style="color:{SEVERITY_COLORS[sev]}">{counts[sev]}</div>
              <div class="stat-label">{sev}</div>
            </div>"""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secret &amp; Crypto Scan Report</title>
<style>
  :root {{
    --bg: #0b0f19; --panel:#121826; --panel2:#161d2e; --border:#232b3d;
    --text:#e6e9f0; --muted:#8a93a6; --accent:#6366f1;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin:0; padding:0; background:var(--bg); color:var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }}
  .mono {{ font-family: "SF Mono", Consolas, Monaco, monospace; font-size:0.85em; }}
  header {{
    padding: 28px 32px; border-bottom:1px solid var(--border);
    background: linear-gradient(135deg, #161d2e, #0b0f19);
  }}
  header h1 {{ margin:0 0 4px 0; font-size:22px; }}
  header .sub {{ color:var(--muted); font-size:13px; }}
  main {{ max-width: 1200px; margin: 0 auto; padding: 28px 32px 60px; }}
  .stats {{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap; }}
  .stat-card {{
    background: var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:18px 24px; min-width:120px; text-align:center;
  }}
  .stat-num {{ font-size:32px; font-weight:700; }}
  .stat-label {{ color:var(--muted); font-size:12px; letter-spacing:0.08em; margin-top:4px; }}
  table {{ width:100%; border-collapse: collapse; background:var(--panel); border-radius:10px; overflow:hidden; }}
  thead th {{
    text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.06em;
    color:var(--muted); padding:12px 14px; border-bottom:1px solid var(--border); background:var(--panel2);
  }}
  tbody td {{ padding:12px 14px; border-bottom:1px solid var(--border); vertical-align:top; font-size:13.5px; }}
  tbody tr:hover {{ background: #ffffff05; }}
  .badge {{ padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; white-space:nowrap; }}
  .desc {{ color:var(--muted); max-width:360px; }}
  .preview {{ margin-top:6px; color:#c8cede; background:#00000040; padding:6px 8px; border-radius:6px; overflow-x:auto; white-space:pre; }}
  .empty {{ text-align:center; color:var(--muted); padding:40px !important; }}
  details.fp-details {{ margin-top:24px; color:var(--muted); }}
  details.fp-details summary {{ cursor:pointer; padding:10px 0; }}
  details.fp-details table {{ margin-top:10px; }}
  .section-title {{ font-size:15px; margin: 32px 0 12px; color:var(--text); }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:30px; }}
</style>
</head>
<body>
<header>
  <h1>🔐 Secret &amp; Weak Cryptography Scan Report</h1>
  <div class="sub">Target: <span class="mono">{_esc(scanned_path)}</span> &nbsp;•&nbsp;
  Generated {timestamp} &nbsp;•&nbsp; {summary_dict['files_scanned']} files scanned, {summary_dict['files_skipped']} skipped</div>
</header>
<main>
  <div class="stats">
    {stat_cards}
    <div class="stat-card" style="border-top:4px solid #6366f1">
      <div class="stat-num" style="color:#6366f1">{total}</div>
      <div class="stat-label">TOTAL FINDINGS</div>
    </div>
  </div>

  <h2 class="section-title">Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Location</th><th>Rule</th><th>Value</th><th>Details</th></tr></thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  {fp_section}
</main>
<footer>Generated by AURA Secret Scanner &mdash; values are redacted; never share raw report data containing secrets outside your team.</footer>
</body>
</html>"""


def render_json_report(summary_dict: dict) -> str:
    return json.dumps(summary_dict, indent=2)
