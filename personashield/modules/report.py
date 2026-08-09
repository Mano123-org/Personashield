"""Report generation: JSON, CSV, HTML — all local, no external calls."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from personashield.models import TargetReport

_RISK_COLORS = {
    "NONE": "#6b7280",
    "LOW": "#22c55e",
    "MEDIUM": "#eab308",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}


def safe_filename(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", target.strip()).strip("_").lower()


def to_json(report: TargetReport, path: Path) -> Path:
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def to_csv(report: TargetReport, path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "source", "domain", "email", "username", "phone",
            "has_password", "hash_type", "full_name", "ip_address",
            "breach_date", "description",
        ])
        for b in report.breaches:
            writer.writerow([
                b.source, b.domain or "", b.email or "", b.username or "",
                b.phone or "", b.has_password, b.hash_type or "",
                b.full_name or "", b.ip_address or "", b.breach_date or "",
                b.description or "",
            ])
    return path


def to_html(report: TargetReport, path: Path) -> Path:
    color = _RISK_COLORS.get(report.risk.level.value, "#6b7280")
    rows = "".join(
        f"""
        <tr>
          <td>{b.source}</td>
          <td>{b.breach_date or "-"}</td>
          <td>{", ".join(b.compromised_fields()) or "-"}</td>
          <td>{b.hash_type or "-"}</td>
        </tr>"""
        for b in report.breaches
    )
    reasons = "".join(f"<li>{r}</li>" for r in report.risk.reasons)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PersonaShield Report — {report.target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; }}
  .card {{ max-width: 800px; margin: 0 auto; background:#1e293b; border-radius:12px; padding:2rem; }}
  h1 {{ font-size:1.4rem; margin-top:0; }}
  .badge {{ display:inline-block; padding:.25rem .75rem; border-radius:999px; background:{color}; color:#0f172a; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; }}
  th, td {{ text-align:left; padding:.5rem; border-bottom:1px solid #334155; font-size:.9rem; }}
  .meta {{ color:#94a3b8; font-size:.85rem; }}
</style>
</head>
<body>
  <div class="card">
    <h1>PersonaShield Report</h1>
    <p class="meta">Target: <strong>{report.target}</strong> ({report.target_type.value})</p>
    <p class="meta">Generated: {report.generated_at}</p>
    <p>Risk level: <span class="badge">{report.risk.level.value}</span> (score: {report.risk.score})</p>
    <ul>{reasons}</ul>
    <h2>Breach Records ({len(report.breaches)})</h2>
    <table>
      <thead><tr><th>Source</th><th>Date</th><th>Compromised Fields</th><th>Hash Type</th></tr></thead>
      <tbody>{rows if rows else "<tr><td colspan='4'>No records found.</td></tr>"}</tbody>
    </table>
    <p class="meta" style="margin-top:1.5rem;">Generated locally by PersonaShield. No data was sent to any external service.</p>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path


def generate_reports(report: TargetReport, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = safe_filename(report.target)
    paths = {
        "json": to_json(report, out_dir / f"{base}.json"),
        "csv": to_csv(report, out_dir / f"{base}.csv"),
        "html": to_html(report, out_dir / f"{base}.html"),
    }
    return paths


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
