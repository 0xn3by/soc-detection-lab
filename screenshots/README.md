# Capture real Splunk screenshots

Audit 2026-10-06: this directory contains no screenshots. The existing SVG
branding is decoration, not Splunk output. See [current validation](../docs/VALIDATION.md).

No screenshots are fabricated or included yet. Capture these manually after
[live verification](../setup/log-ingestion.md). Show the query, selected time
range, and enough results to support the claim. Set the account time zone to UTC.
Keep browser credentials, session tokens, unrelated tabs, and host details out
of the image. All shown endpoint data should come from the synthetic fixtures.

1. **`01-ingestion.png`** — Search & Reporting, All time, unique event counts by
   scenario. Show 12 / 3 / 4 / 28, totaling 47. Expand one raw JSON event to show
   `timestamp`, `event_uid`, `hostname`, and `synthetic=true`.
2. **`02-brute-force.png`** — Complete brute-force search and its one row: 8
   failures, `alex`, `linux-web-01`, `192.0.2.50`, 10:00 bucket.
3. **`03-powershell.png`** — PowerShell search and event 001 with process, parent,
   user, host, and encoded/bypass arguments. A second image can show the linked
   script-block text; do not execute the command to create evidence.
4. **`04-admin-account.png`** — Admin search and event 003, actor/target, group
   SID, and time. Show the account-creation correlation query if space allows.
5. **`05-network.png`** — Network search and one row showing 24 attempts / 24
   ports / blocked. Include source, destination, and protocol.
6. **`06-auth-timeline.png`** — Authentication pivot with failures and the
   10:02:50 success visible, sorted by UTC event time. This substantiates the
   escalation reasoning beyond the threshold alone.
7. **`07-dashboard.png`** (optional) — Open Apps → SOC Lab, or
   `http://127.0.0.1:8000/en-US/app/soc_lab/soc_overview`. Capture real populated
   event panels. These are event counts, not severity or confirmed-incident metrics.
8. **`08-triggered-alert.png`** (optional) — If you enable a saved alert, capture
   its actual execution time and result, then disable the historical schedule.

For each image, keep a short caption including query filename, date of capture,
time range, expected versus observed result, and case ID. Update the case copy
with the real search/alert timestamp and job ID. Avoid calling a bucket start
an alert timestamp.

Image files are ignored by default to avoid accidental publication. After
reviewing a selected image, explicitly add it with, for example,
`git add -f screenshots/01-ingestion.png` in your actual Git checkout. Add
Markdown image links only after those files exist; the root README intentionally
has no broken image placeholders.
