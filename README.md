# SOC Detection & Incident Investigation Lab

A personal **Splunk/SIEM lab** with Python-generated security events, four SPL searches, and worked investigations covering alert triage, correlation, severity, escalation and incident documentation.

> Personal cybersecurity lab. All generated activity is controlled, synthetic data. This project does not represent production SOC or enterprise experience.

**Current evidence:** 47 reproducible events, four offline reference findings and 13 passing tests. **Live Splunk ingestion and SPL execution: NOT VERIFIED.** [Validation details](docs/VALIDATION.md).

## What This Project Demonstrates

- Splunk input, index and JSON field-extraction configuration.
- Authentication, PowerShell, privileged-change and network detection logic.
- Log analysis using host, user, process, outcome and time context.
- Alert triage with legitimate explanations and explicit evidence gaps.
- Severity decisions and escalation recommendations based on synthetic evidence.
- Four incident reports and repeatable evidence-based report drafts.

## Architecture

```text
Python generators → JSONL fixtures → Splunk file monitor → soc_lab / soc:json
                         ↓                                     ↓
                 Offline reference checks               SPL search findings
                                                               ↓
                                                Analyst investigation → Report
```

One configured Docker container provides indexing and search. The offline analyzer does not execute SPL. No native endpoint collection is implemented. [Architecture](architecture/architecture.md).

## Technology

| Technology | Role |
| --- | --- |
| Splunk / SPL | Configured SIEM and four searches; live execution pending |
| Python 3.10+ standard library | Generators, reference analysis and report drafts |
| Docker Compose | Single-node Splunk configuration |
| JSON Lines | Synthetic Linux/Windows-style records |

## Detection Scenarios

Status covers the entire scenario; verified evidence is limited to fixtures and offline analysis. Severity is an exercise assessment.

| Scenario | Detection Objective | Evidence | Severity | Status |
| --- | --- | --- | --- | --- |
| [Brute force](scenarios/01-brute-force/README.md) | ≥5 failures per source/host/user in 5 minutes | [12 events](logs/brute-force.jsonl), [case 001](investigations/incident-001.md) | HIGH, provisional | PARTIALLY VERIFIED |
| [PowerShell](scenarios/02-suspicious-powershell/README.md) | Encoded-command or policy-bypass arguments | [3 events](logs/suspicious-powershell.jsonl), [case 002](investigations/incident-002.md) | LOW, known benign fixture | PARTIALLY VERIFIED |
| [Administrator change](scenarios/03-admin-account-creation/README.md) | Successful local Administrators addition | [4 events](logs/admin-account-creation.jsonl), [case 003](investigations/incident-003.md) | HIGH, provisional | PARTIALLY VERIFIED |
| [Network probing](scenarios/04-suspicious-network-activity/README.md) | ≥20 attempts and ≥10 ports per destination/minute | [28 events](logs/suspicious-network.jsonl), [case 004](investigations/incident-004.md) | MEDIUM | PARTIALLY VERIFIED |

## Investigation Workflow

Event → Ingestion → Detection → Triage → Correlation → Severity → Escalation → Incident Report.

[Playbook](docs/triage-playbook.md) · [Final report](reports/final-soc-report.md) · [Interview notes](docs/interview-notes.md).

## Example Investigation

[Case 001](investigations/incident-001.md) starts from an **offline finding**, not an observed Splunk alert: eight failures over 140 seconds. Event IDs 001–009 show a successful login 30 seconds after the last failure, with the same host, user and source.

That sequence warrants provisional **HIGH** severity and recommended senior review. A user correcting a password or stale automation credentials could explain it. Post-login activity and user confirmation are absent; compromise is not established. No escalation was sent.

## Evidence / Screenshots

Inspect the [fixtures](logs/README.md), [offline findings](reports/offline-findings.json) and [executed check output](reports/audit-local.json). **No screenshots are included.** Follow the [capture checklist](screenshots/README.md) after running Splunk. The bundled dashboard exists as XML; rendering is NOT VERIFIED.

## Detection Engineering

Searches use event type, outcome, host/user, source/destination and process arguments. Stable `event_uid` values deduplicate fixtures. Splunk supplies `_time`; [schema notes](docs/event-schema.md) distinguish native-style fields from synthetic enrichment.

Thresholds are teaching choices. Fixed buckets miss boundary-spanning activity; simple PowerShell patterns miss alternate flags and renamed executables. Approved automation, provisioning and scans are legitimate alternatives. Tune with measured baselines and narrow reviewed exceptions. [Methodology](docs/detection-methodology.md).

## Reproduce the Lab

From the repository root with Python 3.10+:

```bash
python3 scripts/generate_events.py
python3 -m unittest discover -s tests -v
python3 scripts/analyze_events.py
```

Follow [Splunk setup](setup/splunk-setup.md) to configure private credentials and review license terms, then:

```bash
docker compose config --quiet
docker compose up -d
```

Open `http://127.0.0.1:8000`, use **All time** and UTC. Fixtures are dated **2026-01-15**. Run the [ingestion checks and four searches](setup/log-ingestion.md); expected unique counts are 12 / 3 / 4 / 28. These are fixture expectations, not observed Splunk results.

## Validation Status

[docs/VALIDATION.md](docs/VALIDATION.md) records per-scenario checks and manual gates. Generators, schema, reference logic and reports passed locally. **NOT VERIFIED — requires local Splunk execution:** ingestion, timestamp extraction, SPL results, dashboard rendering and optional alerts.

## Limitations

Synthetic telemetry only; no enterprise volume, production data, business baseline, native endpoint collection or commercial EDR backend. Escalation is simplified and recommended only. Counts are not detection accuracy or operational performance metrics. No project license has been selected.

## What I Learned

- Correlating success after failures changes urgency; counts alone do not prove compromise.
- PowerShell requires parent and payload context.
- Privileged membership differs from account creation.
- Blocked attempts and completed connections support different impact conclusions.

## Ethical Scope

Controlled personal lab only. Generators write inert text; they do not execute represented attacks, scan external systems or change accounts.
