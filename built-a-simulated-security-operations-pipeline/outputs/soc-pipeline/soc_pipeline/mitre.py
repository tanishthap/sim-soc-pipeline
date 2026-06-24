from __future__ import annotations

from .models import MitreTechnique

TECHNIQUES = {
    "T1003": MitreTechnique("T1003", "OS Credential Dumping", "Credential Access"),
    "T1041": MitreTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1071": MitreTechnique("T1071", "Application Layer Protocol", "Command and Control"),
    "T1078": MitreTechnique("T1078", "Valid Accounts", "Defense Evasion / Persistence / Privilege Escalation / Initial Access"),
    "T1098": MitreTechnique("T1098", "Account Manipulation", "Persistence / Privilege Escalation"),
    "T1105": MitreTechnique("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1110": MitreTechnique("T1110", "Brute Force", "Credential Access"),
}


def get_techniques(technique_ids: list[str]) -> list[MitreTechnique]:
    return [TECHNIQUES[technique_id] for technique_id in technique_ids if technique_id in TECHNIQUES]
