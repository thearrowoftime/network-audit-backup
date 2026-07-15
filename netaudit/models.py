"""Shared data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DeviceType(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Device:
    name: str
    host: str
    device_type: DeviceType = DeviceType.UNKNOWN
    username: str = ""
    password: str = ""
    port: int = 22
    enable_password: str = ""
    platform: str = "cisco_ios"  # cisco_ios | cisco_asa | juniper | generic
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        dtype = data.get("device_type", "unknown")
        try:
            device_type = DeviceType(dtype)
        except ValueError:
            device_type = DeviceType.UNKNOWN
        return cls(
            name=data["name"],
            host=data["host"],
            device_type=device_type,
            username=data.get("username", ""),
            password=data.get("password", ""),
            port=int(data.get("port", 22)),
            enable_password=data.get("enable_password", ""),
            platform=data.get("platform", "cisco_ios"),
            tags=list(data.get("tags", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["device_type"] = self.device_type.value
        return d


@dataclass
class BackupMeta:
    device: str
    timestamp: str
    path: str
    sha256: str
    size_bytes: int
    source: str = "ssh"  # ssh | file | demo

    @classmethod
    def now_iso(cls) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    device: str
    detail: str
    line: int | None = None
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "device": self.device,
            "detail": self.detail,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class DiffResult:
    device: str
    older: str
    newer: str
    added: list[str]
    removed: list[str]
    changed_hunks: list[str]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed_hunks)
