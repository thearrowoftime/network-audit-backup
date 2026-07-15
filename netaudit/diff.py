"""Config diff between backup snapshots."""

from __future__ import annotations

import difflib
from pathlib import Path

from netaudit.models import DiffResult
from netaudit.store import ConfigStore


def _normalize_lines(text: str) -> list[str]:
    """Normalize for meaningful diffs (strip trailing whitespace, drop blank noise)."""
    lines = [ln.rstrip() for ln in text.splitlines()]
    # Drop Cisco "Building configuration..." / "Current configuration" headers noise optionally kept
    return lines


def diff_texts(device: str, older_label: str, newer_label: str, old: str, new: str) -> DiffResult:
    old_lines = _normalize_lines(old)
    new_lines = _normalize_lines(new)

    sm = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    hunks: list[str] = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            for ln in new_lines[j1:j2]:
                added.append(ln)
        elif tag == "delete":
            for ln in old_lines[i1:i2]:
                removed.append(ln)
        elif tag == "replace":
            for ln in old_lines[i1:i2]:
                removed.append(ln)
            for ln in new_lines[j1:j2]:
                added.append(ln)

    unified = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"{device}:{older_label}",
        tofile=f"{device}:{newer_label}",
        lineterm="",
    )
    hunks = list(unified)

    return DiffResult(
        device=device,
        older=older_label,
        newer=newer_label,
        added=added,
        removed=removed,
        changed_hunks=hunks,
    )


def diff_backups(
    store: ConfigStore,
    device: str,
    older_ts: str | None = None,
    newer_ts: str | None = None,
) -> DiffResult:
    """
    Diff two backups. Defaults: previous vs latest.
    """
    backups = store.list_backups(device)
    if len(backups) < 1:
        raise FileNotFoundError(f"No backups for {device}")

    if newer_ts is None:
        newer_meta = backups[-1]
    else:
        matches = [b for b in backups if b.timestamp == newer_ts]
        if not matches:
            raise FileNotFoundError(f"Backup not found: {device} @ {newer_ts}")
        newer_meta = matches[0]

    if older_ts is None:
        # previous before newer
        idx = next(i for i, b in enumerate(backups) if b.timestamp == newer_meta.timestamp)
        if idx == 0:
            raise FileNotFoundError(f"Only one backup for {device} — nothing to diff")
        older_meta = backups[idx - 1]
    else:
        matches = [b for b in backups if b.timestamp == older_ts]
        if not matches:
            raise FileNotFoundError(f"Backup not found: {device} @ {older_ts}")
        older_meta = matches[0]

    old_text = Path(older_meta.path).read_text(encoding="utf-8")
    new_text = Path(newer_meta.path).read_text(encoding="utf-8")
    return diff_texts(device, older_meta.timestamp, newer_meta.timestamp, old_text, new_text)


def format_diff_markdown(result: DiffResult) -> str:
    lines = [
        f"# Config diff: `{result.device}`",
        "",
        f"- **Older:** `{result.older}`",
        f"- **Newer:** `{result.newer}`",
        f"- **Added lines:** {len(result.added)}",
        f"- **Removed lines:** {len(result.removed)}",
        "",
    ]
    if not result.has_changes:
        lines.append("_No changes._")
        return "\n".join(lines)

    lines.append("```diff")
    lines.extend(result.changed_hunks)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
