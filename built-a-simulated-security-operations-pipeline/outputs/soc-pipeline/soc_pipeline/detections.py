from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from .ioc import extract_iocs
from .mitre import get_techniques
from .models import Alert, LogEvent
from .triage import score_alert


def _alert_id(rule_id: str, events: list[LogEvent]) -> str:
    seed = rule_id + "|" + "|".join(event.event_id for event in events)
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]


def _build_alert(
    *,
    rule_id: str,
    title: str,
    description: str,
    base_severity: str,
    events: list[LogEvent],
    technique_ids: list[str],
    recommended_actions: list[str],
) -> Alert:
    score, severity, priority = score_alert(base_severity, events)
    return Alert(
        alert_id=_alert_id(rule_id, events),
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        severity_score=score,
        priority=priority,
        events=sorted(events, key=lambda event: event.timestamp),
        techniques=get_techniques(technique_ids),
        iocs=extract_iocs(events),
        recommended_actions=recommended_actions,
    )


def detect_brute_force(events: list[LogEvent]) -> list[Alert]:
    auth_events = [
        event
        for event in events
        if event.event_type == "auth" and event.action == "login"
    ]
    failures_by_actor: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    successes_by_actor: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)

    for event in auth_events:
        key = (event.username, event.source_ip)
        if event.status == "failure":
            failures_by_actor[key].append(event)
        elif event.status == "success":
            successes_by_actor[key].append(event)

    alerts: list[Alert] = []
    for key, failures in failures_by_actor.items():
        failures = sorted(failures, key=lambda event: event.timestamp)
        window_start = failures[0].timestamp
        window_failures = [
            event
            for event in failures
            if event.timestamp - window_start <= timedelta(minutes=10)
        ]
        if len(window_failures) < 5:
            continue

        last_failure = window_failures[-1].timestamp
        followup_success = next(
            (
                event
                for event in successes_by_actor.get(key, [])
                if timedelta(0) <= event.timestamp - last_failure <= timedelta(minutes=15)
            ),
            None,
        )
        detection_events = window_failures + ([followup_success] if followup_success else [])
        title = "Successful login after brute force pattern" if followup_success else "Brute force login pattern"
        technique_ids = ["T1110", "T1078"] if followup_success else ["T1110"]
        alerts.append(
            _build_alert(
                rule_id="AUTH-001",
                title=title,
                description=(
                    f"{len(window_failures)} failed logins for {key[0]} from {key[1]} "
                    "were observed inside a 10 minute window."
                ),
                base_severity="critical" if followup_success else "high",
                events=detection_events,
                technique_ids=technique_ids,
                recommended_actions=[
                    "Disable or reset the affected account until ownership is verified.",
                    "Review VPN and identity-provider logs for additional source IPs.",
                    "Confirm whether the successful login created new sessions or tokens.",
                ],
            )
        )
    return alerts


def detect_suspicious_processes(events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "process":
            continue
        command = event.command_line.lower()
        process = event.process_name.lower()
        matched = False
        technique_ids: list[str] = []
        title = "Suspicious process execution"
        base = "high"

        if "powershell" in process and any(
            token in command
            for token in (" -enc", "-encodedcommand", "downloadstring", "invoke-webrequest", " iwr ")
        ):
            matched = True
            technique_ids = ["T1059", "T1105"]
            title = "Encoded PowerShell download activity"
        elif "certutil" in process and "-urlcache" in command:
            matched = True
            technique_ids = ["T1105"]
            title = "Certutil payload transfer activity"
        elif "mimikatz" in command or "sekurlsa" in command:
            matched = True
            technique_ids = ["T1003"]
            title = "Credential dumping indicator"
            base = "critical"

        if matched:
            alerts.append(
                _build_alert(
                    rule_id="PROC-001",
                    title=title,
                    description=f"{event.host} ran {event.process_name}: {event.command_line}",
                    base_severity=base,
                    events=[event],
                    technique_ids=technique_ids,
                    recommended_actions=[
                        "Isolate the endpoint if the command was not approved change activity.",
                        "Acquire process tree, command history, and related file hashes.",
                        "Search endpoint telemetry for the same command line or hash.",
                    ],
                )
            )
    return alerts


def detect_privilege_escalation(events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        text = f"{event.action} {event.command_line} {event.message}".lower()
        if event.event_type not in {"identity", "privilege"}:
            continue
        if any(token in text for token in ("domain admins", "grant_admin", "sudoers", "add_member")):
            alerts.append(
                _build_alert(
                    rule_id="ID-001",
                    title="Privileged group membership change",
                    description=f"{event.username} modified privileged access on {event.host}: {event.message}",
                    base_severity="critical",
                    events=[event],
                    technique_ids=["T1098"],
                    recommended_actions=[
                        "Validate the change ticket and business owner.",
                        "Remove unauthorized group membership immediately.",
                        "Review recent activity for both the admin actor and the newly privileged user.",
                    ],
                )
            )
    return alerts


def detect_beaconing(events: list[LogEvent]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "network" and event.action == "connection" and event.status == "allowed":
            destination = event.destination_domain or event.destination_ip
            if destination:
                grouped[(event.host, destination)].append(event)

    alerts: list[Alert] = []
    for (host, destination), group in grouped.items():
        group = sorted(group, key=lambda event: event.timestamp)
        if len(group) < 4:
            continue
        span = group[-1].timestamp - group[0].timestamp
        if span <= timedelta(minutes=30):
            alerts.append(
                _build_alert(
                    rule_id="NET-001",
                    title="Periodic outbound beaconing pattern",
                    description=(
                        f"{host} contacted {destination} {len(group)} times over "
                        f"{int(span.total_seconds() // 60)} minutes."
                    ),
                    base_severity="high",
                    events=group,
                    technique_ids=["T1071"],
                    recommended_actions=[
                        "Block the destination at egress controls while investigation continues.",
                        "Review DNS, proxy, and endpoint telemetry for related callbacks.",
                        "Check the host for persistence mechanisms and recently spawned processes.",
                    ],
                )
            )
    return alerts


def detect_large_exfiltration(events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "network":
            continue
        if event.bytes_out < 50 * 1024 * 1024:
            continue
        destination = event.destination_domain or event.destination_ip
        alerts.append(
            _build_alert(
                rule_id="NET-002",
                title="Large outbound data transfer",
                description=(
                    f"{event.host} sent {event.bytes_out:,} bytes to {destination}."
                ),
                base_severity="high",
                events=[event],
                technique_ids=["T1041", "T1071"],
                recommended_actions=[
                    "Confirm whether the transfer was approved business activity.",
                    "Review file access logs for sensitive data touched before upload.",
                    "Preserve proxy logs and destination metadata for escalation.",
                ],
            )
        )
    return alerts


def run_detections(events: list[LogEvent]) -> list[Alert]:
    alerts = []
    for detector in (
        detect_brute_force,
        detect_suspicious_processes,
        detect_privilege_escalation,
        detect_beaconing,
        detect_large_exfiltration,
    ):
        alerts.extend(detector(events))
    return sorted(alerts, key=lambda alert: (-alert.severity_score, alert.alert_id))
