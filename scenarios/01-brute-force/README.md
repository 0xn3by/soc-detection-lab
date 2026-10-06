# 01 — Repeated authentication failures

## Objective and source

Find at least five failed SSH logins for the same source, host, and username in
one five-minute bucket. Input is synthetic normalized Linux authentication data.

```bash
python3 scripts/generate_auth_events.py
```

Inspect [the 12 records](../../logs/brute-force.jsonl) before searching. Eight
failures target `alex` from `192.0.2.50`; a later success requires investigation.
Two failures and a success for `sam` from `192.0.2.20` are the benign control.
No network authentication attempts are actually made.

## Detection

Run [brute-force.spl](../../detections/brute-force.spl) in Splunk, All time:

```spl
index=soc_lab sourcetype="soc:json" event_type="authentication" result="failure"
| dedup event_uid
| bin _time span=5m
| stats count AS failed_attempts values(event_uid) AS evidence BY _time hostname username src_ip
| where failed_attempts >= 5
| sort _time
```

- `event_type` selects authentication and `result` selects failures only.
- `event_uid` uniquely identifies each simulated event; dedup avoids counting
  replayed copies twice. `evidence` retains the IDs after aggregation.
- `_time` is parsed event time and becomes the start of a five-minute bucket.
- `hostname`, `username`, and `src_ip` keep different hosts, users, and sources
  separate. `failed_attempts` is a derived count, not a source field.
- `where` applies the **5 failures / 5 minutes** lab threshold; `sort` orders output.

Expected: **one row, 8 failures**, 2026-01-15 10:00:00 UTC bucket, `linux-web-01`,
`alex`, `192.0.2.50`. Evidence is `brute-force-001` through `brute-force-008`.
The rule does not require a success and does not prove compromise.

## Triage and correlation

```spl
index=soc_lab sourcetype="soc:json" hostname="linux-web-01" username="alex" src_ip="192.0.2.50"
| dedup event_uid
| sort 0 _time
| table _time event_uid hostname username src_ip process auth_method result
```

1. Confirm the eight failures span 10:00:00–10:02:20 UTC.
2. Identify `brute-force-009`, successful password login at 10:02:50 UTC.
3. Compare the `sam` control. Same-host activity by a different user/source does
   not contribute to the alert's threshold.
4. Hypothesize password guessing with possible access. Check user confirmation,
   source ownership, authentication baseline, and post-login commands in a real
   case; those sources are absent here.
5. Assign HIGH and recommend escalation because a successful session follows the
   burst. Do not claim that the success was caused by guessing.
6. Recommend session review, credential reset if unauthorized, access restriction,
   SSH key/MFA controls where supported, and rate limiting.

## False positives, tuning, and evasion

Stale automation credentials, repeated user mistakes, and reconnecting clients
can cause failures. A legitimate user may succeed after correcting a password.
Tune by host role, account baseline, source ownership, and approved automation;
avoid blanket IP allowlists. Five is a teaching threshold, not measured normality.
Slow attempts, distributed sources, password spraying, and events split across
10:04/10:05 fixed buckets can evade this rule. A separate sliding-window or
cross-user/source analysis would be needed for those behaviors.

## Complete workflow

Simulated activity → JSONL → monitored Splunk input → search finding → identity
triage → collect IDs 001–009 → correlate the success → credential-attack hypothesis
→ consider user error → suspected access incident → HIGH → recommended escalation
→ conditional containment/hardening → [incident 001](../../investigations/incident-001.md).

Behavior mapping: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/).
This is an illustrative hypothesis, not confirmation of an actual adversary.
