from __future__ import annotations

from .ioc import is_internal_ip
from .models import LogEvent

BASE_SCORES = {
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}


def priority_from_score(score: int) -> str:
    if score >= 90:
        return "P1"
    if score >= 70:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_alert(base_severity: str, events: list[LogEvent]) -> tuple[int, str, str]:
    score = BASE_SCORES[base_severity]
    usernames = {event.username.lower() for event in events}
    external_ips = {
        event.destination_ip
        for event in events
        if event.destination_ip and not is_internal_ip(event.destination_ip)
    } | {
        event.source_ip
        for event in events
        if event.source_ip and not is_internal_ip(event.source_ip)
    }

    if any(name in usernames for name in {"admin", "administrator", "root", "svc-backup"}):
        score += 8
    if external_ips:
        score += 5
    if any(event.file_hash for event in events):
        score += 5
    if any(event.bytes_out >= 50 * 1024 * 1024 for event in events):
        score += 10
    if len(events) >= 5:
        score += 5

    capped = min(score, 100)
    return capped, severity_from_score(capped), priority_from_score(capped)
