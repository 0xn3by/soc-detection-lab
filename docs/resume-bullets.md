# Resume evidence — personal project

## Three bullet options

- Built a Splunk-oriented personal SOC lab with four SPL searches and Python generators producing 47 reproducible synthetic authentication, PowerShell, account-change and network events.
- Investigated four synthetic security scenarios, correlating event timelines, identities and outcomes to document false-positive considerations, severity and escalation recommendations.
- Validated generators, field contracts, reference detection thresholds and evidence-based report generation through 13 passing local tests; explicitly tracked pending live Splunk verification.

## Concise project description

Personal Splunk/SIEM detection and investigation lab with deterministic telemetry, four SPL searches and documented analyst decisions from triage through incident reporting.

## Technology list

Splunk SPL/app configuration, Python standard library, Docker Compose, Linux, JSON Lines, synthetic Windows/Sysmon-style and Linux-style events, Markdown and MITRE ATT&CK references.

## Strongest measured facts

- 47 generated fixture records: 12 authentication, 3 PowerShell, 4 account/group and 28 network.
- Four offline reference findings, including eight authentication failures and 24 blocked attempts to 24 ports.
- 13 tests passed; four report drafts generated with overwrite refusal checked.

[Executed output](../reports/audit-local.json) · [Validation](VALIDATION.md).

These counts describe fixtures and local checks, not Splunk results, detection accuracy or production impact. Live Splunk ingestion/search execution is NOT VERIFIED. Do not claim enterprise monitoring, real incidents, actual escalations or employment experience.
