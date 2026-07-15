"""Wazuh SIEM integration — JSON events for agent logcollector."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

from netaudit.models import Finding, Severity

# Map netaudit severity -> Wazuh rule level (approx)
SEVERITY_TO_LEVEL: dict[str, int] = {
    Severity.CRITICAL.value: 12,
    Severity.HIGH.value: 10,
    Severity.MEDIUM.value: 7,
    Severity.LOW.value: 5,
    Severity.INFO.value: 3,
}


def finding_to_wazuh_event(finding: Finding, source: str = "netaudit") -> dict[str, Any]:
    """One NDJSON event consumable by Wazuh JSON decoder / localfile."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "timestamp": now,
        "integration": source,
        "netaudit": {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "device": finding.device,
            "detail": finding.detail,
            "line": finding.line,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "wazuh_level": SEVERITY_TO_LEVEL.get(finding.severity.value, 5),
        },
    }


def export_wazuh_ndjson(findings: list[Finding], path: str | Path, append: bool = True) -> Path:
    """
    Write one JSON object per line (NDJSON).

    Point a Wazuh agent <localfile> with log_format=json at this file.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and p.exists() else "w"
    with p.open(mode, encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(finding_to_wazuh_event(f), ensure_ascii=False) + "\n")
    return p


def send_wazuh_syslog(
    findings: list[Finding],
    host: str,
    port: int = 514,
    protocol: str = "udp",
) -> int:
    """
    Send findings as syslog-framed JSON to a Wazuh manager / syslog collector.

    Returns number of messages sent.
    """
    proto = protocol.lower()
    sent = 0
    for f in findings:
        event = finding_to_wazuh_event(f)
        # PRI = local0.info (142) — Wazuh can decode JSON body
        msg = f'<142>netaudit: {json.dumps(event, ensure_ascii=False)}'
        data = msg.encode("utf-8")
        if proto == "tcp":
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.sendall(data + b"\n")
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(data, (host, port))
            finally:
                sock.close()
        sent += 1
    return sent


def send_wazuh_api(
    findings: list[Finding],
    base_url: str,
    user: str,
    password: str,
    verify_ssl: bool = False,
) -> dict[str, Any]:
    """
    Authenticate to Wazuh API and POST events via the manager log ingest path.

    Uses /security/user/authenticate then writes via a temporary approach:
    posts JSON events to the custom API endpoint if available, otherwise
    returns a payload you can pipe. Primary production path remains NDJSON+agent.

    For Wazuh 4.x we use PUT-style upload to agents is limited; this helper
    authenticates and posts each event to `/events` when the manager supports it,
    falling back to documenting the NDJSON path on failure.
    """
    base = base_url.rstrip("/")
    # Basic auth -> JWT
    auth_url = f"{base}/security/user/authenticate"
    req = request.Request(auth_url, method="GET")
    import base64

    token_hdr = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token_hdr}")

    ctx = None
    if not verify_ssl:
        import ssl

        ctx = ssl._create_unverified_context()  # noqa: S323 — lab/homelab convenience

    try:
        with request.urlopen(req, context=ctx, timeout=30) as resp:
            auth_body = json.loads(resp.read().decode())
        token = auth_body.get("data", {}).get("token")
        if not token:
            raise RuntimeError(f"No token in Wazuh auth response: {auth_body}")
    except error.HTTPError as exc:
        raise RuntimeError(f"Wazuh auth failed: HTTP {exc.code}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Wazuh API unreachable: {exc.reason}") from exc

    # Wazuh has no universal "inject alert" REST for arbitrary JSON in all versions.
    # We POST to a manager-side script-friendly endpoint: archive via syslog is preferred.
    # Attempt /events (Cloud / some builds); on 404 return token-ok + advise NDJSON.
    events = [finding_to_wazuh_event(f) for f in findings]
    events_url = f"{base}/events"
    payload = json.dumps({"events": events}).encode("utf-8")
    ev_req = request.Request(events_url, data=payload, method="POST")
    ev_req.add_header("Authorization", f"Bearer {token}")
    ev_req.add_header("Content-Type", "application/json")

    try:
        with request.urlopen(ev_req, context=ctx, timeout=30) as resp:
            body = resp.read().decode()
            return {"ok": True, "status": resp.status, "body": body, "count": len(events)}
    except error.HTTPError as exc:
        if exc.code in (404, 405):
            return {
                "ok": False,
                "authenticated": True,
                "count": len(events),
                "message": (
                    "API login OK, but /events is not available on this manager. "
                    "Use --wazuh-file (agent localfile) or --wazuh-syslog instead."
                ),
                "events": events,
            }
        raise RuntimeError(f"Wazuh /events failed: HTTP {exc.code}") from exc
