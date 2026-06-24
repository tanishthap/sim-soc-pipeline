from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    event_type: str
    host: str
    username: str
    source_ip: str
    destination_ip: str
    destination_domain: str
    process_name: str
    command_line: str
    file_hash: str
    status: str
    action: str
    bytes_out: int
    message: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        seed = "|".join(
            [
                self.timestamp.isoformat(),
                self.event_type,
                self.host,
                self.username,
                self.action,
                self.message,
            ]
        )
        return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    severity_score: int
    priority: str
    events: list[LogEvent]
    techniques: list[MitreTechnique]
    iocs: dict[str, list[str]]
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "priority": self.priority,
            "mitre_attack": [
                {
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                }
                for technique in self.techniques
            ],
            "iocs": self.iocs,
            "event_count": len(self.events),
            "first_seen": self.events[0].timestamp.isoformat() if self.events else None,
            "last_seen": self.events[-1].timestamp.isoformat() if self.events else None,
            "recommended_actions": self.recommended_actions,
        }
