"""Security and standards audit engine for network configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from netaudit.models import Finding, Severity

# Platforms that use Cisco-style rule packs by default
CISCO_FAMILY = {"cisco_ios", "cisco_asa", "generic", "juniper"}
FORTI_FAMILY = {"fortigate", "fortios"}
SCALANCE_FAMILY = {"scalance", "scalance_xc"}


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    type: str
    patterns: list[str] = field(default_factory=list)
    absent_ok: list[str] = field(default_factory=list)
    remediation: str = ""
    platforms: list[str] = field(default_factory=list)  # empty = all

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            id=data["id"],
            title=data["title"],
            severity=Severity(data["severity"]),
            type=data["type"],
            patterns=list(data.get("patterns", [])),
            absent_ok=list(data.get("absent_ok", [])),
            remediation=(data.get("remediation") or "").strip(),
            platforms=[p.lower() for p in data.get("platforms", [])],
        )

    def applies_to(self, platform: str | None) -> bool:
        if not self.platforms:
            return True
        if not platform:
            return True
        return platform.lower() in self.platforms


def _read_bundled(name: str) -> dict[str, Any]:
    try:
        rules_pkg = resources.files("netaudit.rules")
        text = (rules_pkg / name).read_text(encoding="utf-8")
        return yaml.safe_load(text) or {}
    except (FileNotFoundError, TypeError, AttributeError):
        fallback = Path(__file__).parent / "rules" / name
        return yaml.safe_load(fallback.read_text(encoding="utf-8")) or {}


def load_rules(path: str | Path | None = None, platform: str | None = None) -> list[Rule]:
    """
    Load rules. If path is set, load that file only.
    Otherwise merge default + fortigate + scalance packs, then filter by platform.
    """
    if path:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = [Rule.from_dict(r) for r in raw.get("rules", [])]
    else:
        rules = []
        for name in ("default.yaml", "fortigate.yaml", "scalance.yaml"):
            raw = _read_bundled(name)
            rules.extend(Rule.from_dict(r) for r in raw.get("rules", []))

    if platform:
        rules = [r for r in rules if r.applies_to(platform)]
    return rules


def _line_matches(patterns: list[str], line: str) -> re.Match[str] | None:
    for pat in patterns:
        m = re.search(pat, line)
        if m:
            return m
    return None


def _any_line_matches(patterns: list[str], lines: list[str]) -> bool:
    return any(_line_matches(patterns, ln) for ln in lines)


def _audit_vty_no_acl(device: str, rule: Rule, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    i = 0
    while i < len(lines):
        if re.match(r"(?i)^\s*line\s+vty\b", lines[i]):
            start = i
            block = [lines[i]]
            i += 1
            while i < len(lines) and (
                lines[i].startswith(" ")
                or lines[i].startswith("\t")
                or re.match(
                    r"(?i)^\s+(login|transport|access-class|password|exec-timeout)",
                    lines[i],
                )
            ):
                block.append(lines[i])
                i += 1
            block_text = "\n".join(block)
            if not re.search(r"(?i)\baccess-class\b", block_text):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        device=device,
                        detail="VTY block has no access-class restriction",
                        line=start + 1,
                        evidence=block[0].strip(),
                        remediation=rule.remediation,
                    )
                )
            continue
        i += 1
    return findings


def _audit_fortigate_any_any(device: str, rule: Rule, lines: list[str]) -> list[Finding]:
    """Detect FortiOS firewall policies that accept all -> all (any/any)."""
    findings: list[Finding] = []
    i = 0
    in_policy = False
    while i < len(lines):
        if re.match(r"(?i)^\s*config\s+firewall\s+policy\b", lines[i]):
            in_policy = True
            i += 1
            continue
        if in_policy and re.match(r"(?i)^\s*end\b", lines[i]):
            in_policy = False
            i += 1
            continue
        if in_policy and re.match(r"(?i)^\s*edit\s+\d+", lines[i]):
            start = i
            block = [lines[i]]
            i += 1
            while i < len(lines) and not re.match(r"(?i)^\s*(next|end)\b", lines[i]):
                block.append(lines[i])
                i += 1
            text = "\n".join(block)
            src_all = bool(
                re.search(r"(?i)set\s+srcaddr\s+.*\b(?:all|any)\b", text)
                or re.search(r'(?i)set\s+srcaddr\s+"all"', text)
            )
            dst_all = bool(
                re.search(r"(?i)set\s+dstaddr\s+.*\b(?:all|any)\b", text)
                or re.search(r'(?i)set\s+dstaddr\s+"all"', text)
            )
            accept = bool(re.search(r"(?i)set\s+action\s+accept\b", text))
            service_all = bool(re.search(r"(?i)set\s+service\s+.*\bALL\b", text))
            if src_all and dst_all and accept:
                name_m = re.search(r'(?i)set\s+name\s+"?([^"\n]+)"?', text)
                pname = name_m.group(1).strip() if name_m else "unnamed"
                detail = f"Policy '{pname}' accepts src/dst all"
                if service_all:
                    detail += " with service ALL"
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        device=device,
                        detail=detail,
                        line=start + 1,
                        evidence=block[0].strip()[:120],
                        remediation=rule.remediation,
                    )
                )
            continue
        i += 1
    return findings


def audit_config(
    device: str,
    config: str,
    rules: list[Rule] | None = None,
    platform: str | None = None,
) -> list[Finding]:
    """Run rules against a config string; return findings."""
    if rules is None:
        rules = load_rules(platform=platform)
    else:
        rules = [r for r in rules if r.applies_to(platform)]

    lines = config.splitlines()
    findings: list[Finding] = []

    for rule in rules:
        if rule.type == "regex":
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("!") or stripped.startswith("#"):
                    continue
                if _line_matches(rule.patterns, line):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            device=device,
                            detail=f"Matched insecure pattern on line {idx}",
                            line=idx,
                            evidence=stripped[:200],
                            remediation=rule.remediation,
                        )
                    )

        elif rule.type == "missing":
            if not _any_line_matches(rule.patterns, lines):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        device=device,
                        detail="Required configuration not found",
                        remediation=rule.remediation,
                    )
                )

        elif rule.type == "presence_default":
            has_bad = _any_line_matches(rule.patterns, lines)
            has_ok = _any_line_matches(rule.absent_ok, lines) if rule.absent_ok else False
            if has_bad or (rule.absent_ok and not has_ok):
                evidence = ""
                line_no = None
                for idx, line in enumerate(lines, start=1):
                    if _line_matches(rule.patterns, line):
                        evidence = line.strip()
                        line_no = idx
                        break
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        device=device,
                        detail=rule.title,
                        line=line_no,
                        evidence=evidence or "(default / not explicitly disabled)",
                        remediation=rule.remediation,
                    )
                )

        elif rule.type == "vty_no_acl":
            findings.extend(_audit_vty_no_acl(device, rule, lines))

        elif rule.type == "fortigate_any_any":
            findings.extend(_audit_fortigate_any_any(device, rule, lines))

    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.rule_id, f.line or 0))
    return findings


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    counts["total"] = len(findings)
    return counts


def infer_platform_from_config(config: str) -> str | None:
    """Best-effort platform guess for --file audits."""
    if re.search(r"(?i)^\s*config\s+system\s+global\b", config, re.M) or re.search(
        r"(?i)^\s*config\s+firewall\s+policy\b", config, re.M
    ):
        return "fortigate"
    if re.search(r"(?i)^\s*cli[#>]", config, re.M) or re.search(
        r"(?i)SCALANCE\s+XC", config
    ):
        return "scalance"
    if re.search(r"(?i)^\s*hostname\b", config, re.M) or re.search(
        r"(?i)^\s*version\s+\d", config, re.M
    ):
        return "cisco_ios"
    return None
