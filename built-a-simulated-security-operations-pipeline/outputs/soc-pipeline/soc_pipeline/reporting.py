from __future__ import annotations

from .models import Alert


def render_llm_prompt(alert: Alert) -> str:
    timeline = "\n".join(
        f"- {event.timestamp.isoformat()} {event.host} {event.username} {event.event_type}/{event.action}: {event.message}"
        for event in alert.events
    )
    techniques = ", ".join(
        f"{technique.technique_id} {technique.name}" for technique in alert.techniques
    )
    return f"""You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: {alert.title}
Severity: {alert.severity} ({alert.severity_score})
MITRE ATT&CK: {techniques}
IOCs: {alert.iocs}
Timeline:
{timeline}
"""


def render_alert_report(alert: Alert) -> str:
    techniques = "\n".join(
        f"- {technique.technique_id}: {technique.name} ({technique.tactic})"
        for technique in alert.techniques
    )
    iocs = "\n".join(
        f"- {kind}: {', '.join(values)}" for kind, values in alert.iocs.items()
    ) or "- None extracted"
    timeline = "\n".join(
        "- "
        f"{event.timestamp.isoformat()} | {event.host} | {event.username} | "
        f"{event.event_type}/{event.action} | {event.message}"
        for event in alert.events
    )
    actions = "\n".join(f"- {action}" for action in alert.recommended_actions)

    return f"""## {alert.priority} {alert.title}

**Alert ID:** {alert.alert_id}
**Rule:** {alert.rule_id}
**Severity:** {alert.severity.upper()} ({alert.severity_score}/100)

### SOC Summary
{alert.description}

### MITRE ATT&CK Mapping
{techniques}

### Extracted IOCs
{iocs}

### Investigation Timeline
{timeline}

### Recommended Actions
{actions}

### LLM Prompt Used For Analyst Summary
```text
{render_llm_prompt(alert).strip()}
```
"""


def render_case_report(alerts: list[Alert]) -> str:
    critical = sum(1 for alert in alerts if alert.severity == "critical")
    high = sum(1 for alert in alerts if alert.severity == "high")
    medium = sum(1 for alert in alerts if alert.severity == "medium")
    low = sum(1 for alert in alerts if alert.severity == "low")
    report_sections = "\n\n".join(render_alert_report(alert) for alert in alerts)

    return f"""# SOC Investigation Report

## Triage Overview

- Total alerts: {len(alerts)}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}

The queue is sorted by severity score so the highest-risk investigations are reviewed first.

{report_sections}
"""
