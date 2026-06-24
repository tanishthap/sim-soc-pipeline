from __future__ import annotations

import csv
import json
from pathlib import Path

from .detections import run_detections
from .loader import load_csv
from .models import Alert
from .reporting import render_case_report


def write_alerts_json(alerts: list[Alert], path: Path) -> None:
    path.write_text(
        json.dumps([alert.to_dict() for alert in alerts], indent=2),
        encoding="utf-8",
    )


def write_triage_csv(alerts: list[Alert], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "priority",
                "severity",
                "severity_score",
                "alert_id",
                "rule_id",
                "title",
                "event_count",
                "mitre_techniques",
                "first_seen",
                "last_seen",
            ],
        )
        writer.writeheader()
        for alert in alerts:
            row = alert.to_dict()
            writer.writerow(
                {
                    "priority": alert.priority,
                    "severity": alert.severity,
                    "severity_score": alert.severity_score,
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "title": alert.title,
                    "event_count": len(alert.events),
                    "mitre_techniques": "; ".join(
                        technique["technique_id"] for technique in row["mitre_attack"]
                    ),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
            )


def run_pipeline(input_path: str | Path, output_dir: str | Path) -> list[Alert]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    events = load_csv(input_path)
    alerts = run_detections(events)

    write_alerts_json(alerts, output / "alerts.json")
    write_triage_csv(alerts, output / "triage_queue.csv")
    (output / "soc_investigation_report.md").write_text(
        render_case_report(alerts),
        encoding="utf-8",
    )
    return alerts
