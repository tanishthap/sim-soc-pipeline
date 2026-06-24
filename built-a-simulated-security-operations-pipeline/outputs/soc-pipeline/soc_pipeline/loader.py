from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from .models import LogEvent


def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _int_or_zero(value: str | None) -> int:
    if not value:
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def load_csv(path: str | Path) -> list[LogEvent]:
    events: list[LogEvent] = []
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            clean = {key: (value or "").strip() for key, value in row.items()}
            events.append(
                LogEvent(
                    timestamp=parse_timestamp(clean["timestamp"]),
                    event_type=clean.get("event_type", "").lower(),
                    host=clean.get("host", ""),
                    username=clean.get("username", ""),
                    source_ip=clean.get("source_ip", ""),
                    destination_ip=clean.get("destination_ip", ""),
                    destination_domain=clean.get("destination_domain", ""),
                    process_name=clean.get("process_name", "").lower(),
                    command_line=clean.get("command_line", ""),
                    file_hash=clean.get("file_hash", ""),
                    status=clean.get("status", "").lower(),
                    action=clean.get("action", "").lower(),
                    bytes_out=_int_or_zero(clean.get("bytes_out")),
                    message=clean.get("message", ""),
                    raw=clean,
                )
            )
    return sorted(events, key=lambda event: event.timestamp)
