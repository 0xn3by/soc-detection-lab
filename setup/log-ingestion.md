# Ingestion and search verification

## Configuration

The bundled app creates `soc_lab` in [indexes.conf](splunk-app/local/indexes.conf).
[inputs.conf](splunk-app/local/inputs.conf) monitors `/lab/logs/*.jsonl` and assigns
`sourcetype=soc:json`. [props.conf](splunk-app/local/props.conf) separates events
at newlines, reads `timestamp` as UTC, and extracts JSON fields at search time
with `KV_MODE=json`. Do not also enable indexed JSON extraction; duplicate
extraction can produce unexpected multivalue fields.

`MAX_DAYS_AGO=3650` permits the fixed historical fixture date for this lab.
`_time` is the parsed event time; `_indextime` is when Splunk received the event.
The JSON `hostname` identifies the simulated endpoint. Splunk's metadata `host`
may identify the collecting container and is not used as the endpoint field.

No manual file upload is needed. On startup Splunk reads the mounted files.
Regeneration leaves identical files untouched. File monitor checkpoints persist
in the volume, so regeneration is not a new attack and will not necessarily
reingest events. Do not copy the same fixtures under new names to force ingestion.

## Verify arrival

In Search & Reporting select **All time**, then run:

```spl
index=soc_lab sourcetype="soc:json"
| stats count AS raw_events dc(event_uid) AS unique_events BY scenario
```

Expected unique counts are 12 brute-force, 3 suspicious-powershell,
4 admin-account-creation, and 28 suspicious-network: **47 total**. On a clean
ingestion raw counts equal unique counts. Extra raw counts indicate duplicate
ingestion; detections deduplicate by `event_uid` so fixture copies do not inflate
thresholds. Stable IDs are specific to these fixtures, not a production identity scheme.

```spl
index=soc_lab sourcetype="soc:json"
| dedup event_uid
| eval parsed_time=strftime(_time,"%Y-%m-%dT%H:%M:%SZ")
| table timestamp parsed_time _indextime event_uid hostname username event_type result
| sort timestamp
```

With account timezone UTC, `parsed_time` must equal `timestamp`; first event is
`2026-01-15T10:00:00Z`, last is `2026-01-15T10:30:46Z`. Verify the JSON fields
are scalar and present before proceeding.

## Execute the four detections

Paste each file's complete contents into Search & Reporting with All time:

1. [brute-force.spl](../detections/brute-force.spl): one row, 8 failures, `alex`,
   `192.0.2.50`, `linux-web-01`, 10:00 five-minute bucket.
2. [suspicious-powershell.spl](../detections/suspicious-powershell.spl): one row,
   `suspicious-powershell-001`, `LAB\jordan`, `winword.exe` parent.
3. [admin-account-creation.spl](../detections/admin-account-creation.spl): one row,
   `admin-account-creation-003`, `lab_backup`, local Administrators group.
4. [suspicious-network.spl](../detections/suspicious-network.spl): one row,
   24 attempts / 24 ports, destination `198.51.100.20`, 10:30 minute bucket.

Use the scenario correlation queries to expand the initial finding into a
timeline. A search row is a finding; it becomes a classified incident only after
analyst review. Capture the actual search time, SID/job URL if available, search
text, time range, and result in the report. The provided investigations are
worked examples based on local fixtures, not claims of executed Splunk searches.

## Optional saved alerts

For this historical replay, use **Save As → Report** to preserve each search.
If your Splunk license supports alerts, **Save As → Alert**, scheduled every
5 minutes, time range All time, trigger when result count > 0, action **Add to
Triggered Alerts**, and no email/webhook. Name them `LAB - <scenario>`.
Disable the schedule after observing one run: historical events continue matching.
Keep screenshots of the actual triggered alert, not a fabricated example.

A future live pipeline would use a bounded lookback, ingestion-delay allowance,
overlap, and suppression keys. Simply using Last 15 minutes on this historical
dataset returns no findings. Threshold queries use fixed buckets rather than
sliding windows; scheduling cannot remove boundary blind spots.

## Focused troubleshooting

First confirm `python3 scripts/generate_events.py` prints four file counts. Then:

```bash
docker compose exec splunk ls -l /lab/logs
docker compose exec --user splunk splunk /opt/splunk/bin/splunk btool inputs list --debug
docker compose exec --user splunk splunk /opt/splunk/bin/splunk btool props list soc:json --debug
docker compose exec --user splunk splunk /opt/splunk/bin/splunk btool indexes list soc_lab --debug
```

Check effective settings point to the bundled app. In Splunk search:

```spl
index=_internal source="*splunkd.log*" ("/lab/logs" OR "soc_lab")
| table _time log_level component message
```

Use a recent time range for internal diagnostics. Missing fields suggest wrong
sourcetype or JSON extraction; wrong dates suggest timestamp configuration;
zero events with healthy inputs often means the wrong search time range.
Do not treat a zero-result detection as proof of correct ingestion.
