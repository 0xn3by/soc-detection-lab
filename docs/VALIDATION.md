# Validation Status

Audit: 2026-10-06. Overall: **READY WITH MANUAL VALIDATION** for presentation as a synthetic, Splunk-oriented lab. This is not a completed live SIEM validation.

| Scenario | Simulation Tested | Telemetry Verified | Detection Verified | Investigation Evidence Verified | Status |
|---|---|---|---|---|---|
| Brute force | VERIFIED | VERIFIED | PARTIALLY VERIFIED | VERIFIED | PARTIALLY VERIFIED |
| Suspicious PowerShell | VERIFIED | VERIFIED | PARTIALLY VERIFIED | VERIFIED | PARTIALLY VERIFIED |
| Local administrator membership | VERIFIED | VERIFIED | PARTIALLY VERIFIED | VERIFIED | PARTIALLY VERIFIED |
| Suspicious network activity | VERIFIED | VERIFIED | PARTIALLY VERIFIED | VERIFIED | PARTIALLY VERIFIED |

Here “Simulation Tested” means Python generated inert JSON, not that an attack ran.
“Telemetry Verified” means synthetic file contents and schema, not Splunk ingestion.
“Investigation Evidence Verified” means the worked report agrees with those fixtures, not a real incident.
“Detection Verified” is partial because reference Python behavior and SPL field compatibility were checked; no SPL engine executed.

## Executed checks and evidence

[Command output](../reports/audit-local.json) records executed commands and exit codes.
The [publication checks](../reports/audit-review.json) found no broken local
Markdown targets/anchors or high-confidence secret-pattern candidates in the
inspected publishable files. This is not an exhaustive secret guarantee.
The 13-test suite passed, covering reproducible generation, unique IDs, parseable UTC timestamps, required fields, positive/negative controls, thresholds, fixed windows, duplicate ingestion, four report drafts and overwrite refusal, Markdown targets, canonical SPL copies and dashboard XML.

All four scenario generator CLIs and both authentication convenience entry points executed successfully into temporary directories. Output matched committed fixtures. The analyzer reproduced [offline findings](../reports/offline-findings.json): 47 events and four findings. These are not Splunk result counts.

- **Authentication:** 12 source events; eight same-identity failures at 10:00:00–10:02:20, followed by success at 10:02:50. Case 001 separates the low-volume control and recommends HIGH review without claiming compromise.
- **PowerShell:** three source events; event 001 matches the reference predicate. UTF-16LE Base64 decodes as text to the harmless marker and agrees with event 002. Word parent and shared script-block GUID are modeled, not native collection. LOW disposition relies on known fixture provenance.
- **Account/group:** four source events; event 003 is successful membership in SID S-1-5-32-544. Creation event 002 precedes it by eight seconds. The nearby net.exe record supports context, not causal attribution. HIGH is provisional.
- **Network:** 28 source events; 24 blocked attempts to distinct ports within 46 seconds meet both thresholds. Four allowed browser records are separate. MEDIUM reflects suspicious but blocked activity and missing authorization context.

Configuration inspection found consistent `soc_lab`, `soc:json`, `timestamp` and `hostname` contracts. Compose configuration parses with validation-only placeholder variables. Actual Splunk parsing and SPL syntax acceptance remain NOT VERIFIED.

## NOT VERIFIED — requires local Splunk execution

Docker daemon access returned permission denied in this audit session; no accessible Splunk runtime was established. Do not relabel the offline findings as alerts.

1. Follow [setup](../setup/splunk-setup.md): generate fixtures, configure a private .env with your chosen password and license acceptance, then run:
   `docker compose config --quiet`, `docker compose up -d`, `docker compose ps`.
2. Log in at http://127.0.0.1:8000. Select All time and UTC. Run:
   `index=soc_lab sourcetype="soc:json" | stats count AS raw_events dc(event_uid) AS unique_events BY scenario`.
   Expected unique counts: 12 / 3 / 4 / 28. Record actual counts.
3. Run the timestamp/field query in [ingestion](../setup/log-ingestion.md). Compare `_time` with source `timestamp`, including first/last event times.
4. Paste each complete file in `detections/`. Expected results: brute force one row/eight failures; PowerShell event 001; administrator event 003; network one row/24 attempts/24 ports. Record actual query text, time range, job ID, execution time and result export for each.
5. Run each scenario's correlation pivot. Compare report evidence IDs and outcomes. Capture the [screenshots](../screenshots/README.md). Dashboard rendering and any optional saved alert require separate observed evidence.

No screenshots exist. Source SVGs are decorative assets, not application evidence.
Do not substitute bucket/event timestamps for alert execution time.

## Technical review and interview boundaries

The queries' source fields exist in applicable fixtures; aggregate counts are derived fields. Fixed-window limitations and simplified PowerShell matching are documented. No working query was redesigned.

ATT&CK mappings were checked against primary references: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) for the guessing hypothesis, [T1059.001](https://attack.mitre.org/techniques/T1059/001/) for modeled PowerShell, [T1136.001](https://attack.mitre.org/techniques/T1136/001/) for account creation, [T1098.007](https://attack.mitre.org/techniques/T1098/007/) for group addition and [T1046](https://attack.mitre.org/techniques/T1046/) for probing. These describe behavior/hypotheses, not confirmed adversary intent.

README claims are bounded to inspectable source, fixtures and checks. Explain one threshold, one false-positive alternative, why severity differs across cases and why offline tests cannot establish live Splunk operation.
