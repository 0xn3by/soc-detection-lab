# Final SOC lab report

## Scope and validation status

This personal portfolio exercise investigates four fictional security scenarios
using 47 deterministic synthetic events. Python fixtures and reference detections
were tested locally. Splunk configuration and searches are provided; live
ingestion, SPL execution, and screenshots remain to be verified. This report
does not describe employment, a real organization, or an actual compromise.

## Architecture

One Dockerized Splunk instance monitors read-only JSONL files, parses UTC event
time, indexes into `soc_lab`, and extracts `soc:json` fields. Four behavior-based
searches feed manual triage and Markdown investigation reports. No malware,
external scanning, real account changes, or automated response is involved.
See [architecture](../architecture/architecture.md) and [setup](../setup/README.md).

## Investigation summary

“Escalated?” below records the exercise recommendation; **no real escalation
was sent**. Detection times are not invented: each case awaits a real replay
search/alert timestamp. Severity is analyst-assigned after reviewing context.

| Incident | Detection | Severity | Escalated? | Primary evidence | Recommended action |
| --- | --- | --- | --- | --- | --- |
| [LAB-001](../investigations/incident-001.md) | 8 failures in a five-minute bucket | HIGH | Yes, recommended only | brute-force-001–008; success 009 at 10:02:50 UTC | Validate login; revoke/reset if unauthorized; harden SSH |
| [LAB-002](../investigations/incident-002.md) | Encoded/bypass PowerShell | LOW | No; known benign simulation | suspicious-powershell-001/002; harmless decoded script | Document benign disposition; retain focused detection |
| [LAB-003](../investigations/incident-003.md) | Successful local Administrators addition | HIGH | Yes, recommended only | admin-account-creation-002/003; same target/actor/logon label | Verify approval; remove privilege/disable if unauthorized |
| [LAB-004](../investigations/incident-004.md) | 24 attempts to 24 ports in one minute | MEDIUM | Yes, contextual review recommended only | suspicious-network-001–024, all blocked | Validate process/scan owner; preserve block and investigate |

## Findings and reasoning

The credential case is elevated by a later success, but there is no evidence
of what occurred in the session. The PowerShell case demonstrates a benign
positive: suspicious arguments merit review, while known simulation provenance
and harmless decoded content justify closure. The administrator case shows a
completed privileged change; the missing approval context warrants escalation
without asserting that approval was denied. The network case shows a probing
pattern, while blocked outcomes limit observed impact.

No fixture establishes lateral movement, persistence after the administrator
grant, data theft, destructive action, or real business impact. No case is
CRITICAL. These independent exercises do not form a demonstrated attack chain.

## Evidence and repeatability

Source JSONL is retained in [logs](../logs/README.md), and the machine-readable
[offline findings](offline-findings.json) retain exact detection evidence IDs.
Each worked investigation contains all 20 report fields, including uncertainty,
false-positive alternatives, severity, escalation, and conditional remediation.

```bash
python3 scripts/generate_events.py
python3 scripts/analyze_events.py --output reports/offline-findings.json
python3 -m unittest discover -s tests -v
python3 scripts/generate_report.py --scenario brute-force --incident-id LAB-REPLAY-001 --output reports/replay-001.md
```

The report helper populates evidence, hashes, and timelines but leaves analytical
decisions to the analyst. It refuses to overwrite an existing report.

## Lessons learned

- Validate parsing and time ranges before concluding a detector is quiet.
- Correlate successful outcomes and privilege rather than equating counts with harm.
- Preserve evidence IDs and distinguish event time from alert time.
- Explain legitimate alternatives and unknown authorization context.
- Treat native source-field assumptions explicitly; these normalized logs include
  synthetic enrichment that a real collection pipeline would have to supply.
- Fixed-window thresholds and simple argument rules have documented blind spots.
- A local reference test is useful, but actual SIEM execution needs its own evidence.

Next steps are live Splunk replay, [screenshots](../screenshots/README.md), and
capturing actual job IDs/timestamps in case copies. Future authorized endpoint
collection and stronger window logic should come only after this baseline works.
