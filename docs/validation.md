# Validation record and acceptance checklist

## Local validation

The repository was built on a Linux environment with Python 3.14.7, Docker CLI
29.7.2, and Docker Compose 5.5.1. Python tools target 3.10+ syntax; only the listed
local interpreter was executed. The Docker daemon was reachable after permission
was granted. No Splunk image was present at initial inspection.

Local result: **13 tests passed**, Python compilation passed, and
`docker compose config --quiet` passed using non-secret placeholder environment
values. All four generator commands and both convenience entry points ran
successfully. Report drafts for all four scenarios were generated in temporary
directories, and overwrite refusal was verified. Local Markdown targets, the
documented SPL copies, 20-section case structure, and dashboard XML passed checks.

Offline reference detection results are saved in
[offline-findings.json](../reports/offline-findings.json): 47 source events,
one matching finding per scenario, eight authentication failures, and 24 network
attempts across 24 ports. This is fixture acceptance, not a detection-rate metric.

```bash
python3 -m compileall -q scripts tests
python3 scripts/generate_events.py
python3 -m unittest discover -s tests -v
python3 scripts/analyze_events.py --output reports/offline-findings.json
```

Additional checks cover report generation/refusal to overwrite, local Markdown
links, repeated SPL blocks matching canonical files, required case sections, and
dashboard XML parsing. Compose is validated with non-secret placeholder values
without starting the container. None of these checks execute Splunk's search engine.

## Pending live verification

Splunk was not downloaded or started during the build. The example environment
has no password or terms acceptance; you supply these for your installation.
Therefore image startup, actual parsing/ingestion, SPL execution, dashboard
rendering, and saved-alert behavior remain **unverified**. Screenshots are not
present and no alert timestamp/job ID is fabricated. The pinned image version
is a configuration choice, not a claim of tested compatibility or current support.

## Five-minute check after Splunk finishes startup

1. **Minute 1:** Login at `http://127.0.0.1:8000`, set timezone UTC, and choose
   All time. Run the count query from [ingestion](../setup/log-ingestion.md).
   Verify unique counts 12 / 3 / 4 / 28 and raw counts equal unique on fresh ingest.
2. **Minute 2:** Compare `timestamp` to `_time` using the documented format query.
   Verify 2026-01-15 10:00:00 through 10:30:46 UTC and present scalar fields.
3. **Minute 3:** Run brute-force and PowerShell SPL. Expect one row each: eight
   failures, and the modeled Word → PowerShell process with encoded/bypass flags.
4. **Minute 4:** Run admin and network SPL. Expect one local Administrator change,
   and one row with 24 attempts / 24 distinct ports / blocked outcomes.
5. **Minute 5:** Run the authentication pivot, confirm the later success at
   10:02:50 UTC, and capture the query/result. Record actual query time and job ID.

Capture remaining screenshots afterward using the [guide](../screenshots/README.md).
If anything differs, keep validation pending, investigate the effective config,
and fix/retest before updating the README or claiming live SIEM completion.

## Record the actual replay

Copy this section into a replay note and fill only observed values:

- Splunk image tag/digest and displayed version:
- Host platform and Docker/Compose versions:
- Replay date / analyst:
- Input count and unique count by scenario:
- Timestamp/field extraction verification:
- Search file, job ID, result count, and actual execution timestamp (each rule):
- Dashboard rendering / optional alert test:
- Screenshot paths:
- Differences, fixes, and retest results:
- Final acceptance decision:
