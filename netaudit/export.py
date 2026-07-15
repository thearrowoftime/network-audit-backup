"""Export audit findings and diffs to CSV / Markdown."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from netaudit.audit import summarize_findings
from netaudit.diff import DiffResult, format_diff_markdown
from netaudit.models import Finding


def export_findings_csv(findings: list[Finding], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "device",
        "severity",
        "rule_id",
        "title",
        "line",
        "detail",
        "evidence",
        "remediation",
    ]
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            row = f.to_dict()
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    return p


def export_findings_markdown(
    findings: list[Finding],
    path: str | Path,
    title: str = "Network Security Audit Report",
) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarize_findings(findings)

    lines: list[str] = [
        f"# {title}",
        "",
        f"_Generated: {now}_",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|------:|",
        f"| critical | {summary['critical']} |",
        f"| high | {summary['high']} |",
        f"| medium | {summary['medium']} |",
        f"| low | {summary['low']} |",
        f"| info | {summary['info']} |",
        f"| **total** | **{summary['total']}** |",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No findings — configs passed all enabled rules.")
    else:
        for f in findings:
            loc = f" (line {f.line})" if f.line else ""
            lines.append(f"### [{f.severity.value.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **Device:** `{f.device}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Detail:** {f.detail}{loc}")
            if f.evidence:
                lines.append(f"- **Evidence:** `{f.evidence}`")
            if f.remediation:
                lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def export_diff_markdown(result: DiffResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(format_diff_markdown(result), encoding="utf-8")
    return p


def export_diff_csv(result: DiffResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "side", "line"])
        for ln in result.removed:
            writer.writerow([result.device, "removed", ln])
        for ln in result.added:
            writer.writerow([result.device, "added", ln])
    return p
