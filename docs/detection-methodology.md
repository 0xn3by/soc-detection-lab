# Detection engineering method

## Inspect → build → test → investigate

1. Inspect a real fixture line (`head -n 1 logs/brute-force.jsonl`) and enumerate
   the fields for that event type. Read the [schema](event-schema.md).
2. Confirm the input/index/sourcetype and parsed `_time` in Splunk before tuning.
3. Filter by behavior and result, not by scenario or expected attacker labels.
4. Group by identities needed for the question; aggregate only after retaining
   unique evidence IDs. Apply an explicit threshold.
5. Compare expected positives and benign controls. Check just below and at each
   threshold, different identities, duplicates, and fixed-window boundaries.
6. Run the actual SPL in Splunk and capture the query, result, job ID, and time
   range. An offline Python equivalent does not prove SPL syntax or ingestion.
7. Pivot from the detection row to surrounding raw events. Decide confidence,
   impact, classification, severity, escalation, and recommended containment.

## Shared SPL conventions

`index=soc_lab sourcetype="soc:json"` scopes searches to this lab. `dedup
event_uid` prevents duplicate copies of fixed fixtures from increasing counts.
It does not validate log integrity or solve production deduplication. `_time`
comes from Splunk parsing, while endpoint fields come from the JSON.

`bin` uses epoch-aligned, fixed buckets: five minutes for authentication, one
minute for network activity. A result's `_time` is the bucket start, not the
first event or actual alert time. `stats count` counts events; `dc(dest_port)`
counts distinct ports; `values(event_uid)` retains evidence references. `where`
filters aggregated rows or evaluated process indicators. `table` selects useful
triage fields and `sort` orders results. Full explanations and exact SPL live in
the [four scenario guides](../README.md#detection-scenarios).

Thresholds (5 failures / 5 minutes; 20 attempts and 10 ports / minute) are chosen
for a small explainable lab fixture. They are not measured enterprise baselines.
PowerShell and administrator membership searches alert on any matching event.
An event match does not establish malicious intent.

## Correlation and limits

Authentication pivots retain host, user, and source; a success after failures is
a concern, not proof that a password was guessed. The rule itself counts failures
only. Privileged-account triage joins the creation and group event by host,
target account, actor, and logon label. A nearby process is supporting correlation,
not a guaranteed causal link. PowerShell links the synthetic process and script
records, then decodes the content as text without running it. Network investigation
separates blocked attempts from allowed benign browser connections.

Known blind spots include bucket boundaries, slow attempts, source rotation,
password spraying across accounts, abbreviated/obfuscated PowerShell arguments,
renamed executables, direct APIs, unmonitored administrative groups, and missing
telemetry. A scheduled overlapping window helps late ingestion but does not fix
fixed-bucket splitting. Production work would add sliding-window logic where
needed and test event-time versus ingestion-time behavior.

Tune with documented baselines and narrow exceptions that include owner, host,
purpose, and expiry. Do not broadly allowlist PowerShell or all helpdesk activity.
Review both false alerts and missed events after each change.

## Validation artifacts

- [tests](../tests/test_lab.py): deterministic data, behavioral boundaries,
  negative controls, safe payload, and source-field contracts.
- [offline findings](../reports/offline-findings.json): repeatable local rule
  reference results, explicitly labeled offline.
- [validation record](validation.md): what was actually executed and outstanding.
- [screenshots guide](../screenshots/README.md): evidence to capture from Splunk.

Four fixture findings are an acceptance check, not precision/recall, a detection
rate, or a production security outcome.
