# Resume wording — personal security project

## Three bullets supported by the repository today

- Built a personal Splunk SOC lab with Docker configuration, deterministic Python
  telemetry generators, and four SPL detections covering authentication failures,
  suspicious PowerShell, local administrator changes, and scanning-like activity.
- Investigated four synthetic security scenarios by correlating event timelines,
  identities, process context, and outcomes; documented false-positive hypotheses,
  severity rationale, MITRE ATT&CK mappings, and escalation recommendations.
- Implemented repeatable evidence-based report drafts and local tests for detection
  thresholds, benign controls, duplicate events, and log-field consistency across
  47 synthetic events.

## Concise project description

**SOC Detection & Incident Investigation Lab — Personal Project:** A reproducible
Splunk-oriented security lab using Python-generated Linux/Windows-style telemetry,
four behavior-based SPL searches, and documented analyst investigations from
triage through severity and escalation decisions.

## Technologies

Splunk SPL and app configuration, Python standard library, Docker Compose,
Linux/Fedora tooling, JSON Lines, normalized Windows/Sysmon-like telemetry,
Markdown, and MITRE ATT&CK references.

## Skills demonstrated

SIEM ingestion design and field validation; suspicious-activity detection; log
review; process/identity/time correlation; false-positive assessment; incident
classification; severity and escalation reasoning; technical reporting;
reproducible automation and testing.

## Honesty check before submitting

The current bullets describe implemented artifacts and synthetic investigations.
Live Splunk ingestion/search validation is pending in [validation](validation.md).
After verifying it yourself, you may truthfully add “ingested and searched 47
synthetic events in Splunk.” Do not claim live monitoring experience, production
incident response, employer impact, detection rates, or response-time reductions.
