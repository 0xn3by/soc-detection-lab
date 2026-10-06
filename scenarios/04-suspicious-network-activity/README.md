# 04 — Scanning-like outbound attempts

## Objective and source

Find a burst from one source/user/host to one destination across many TCP ports.
The data models an endpoint-enriched firewall; no traffic or scan is generated.

```bash
python3 scripts/generate_events.py --scenario suspicious-network
```

Inspect [the 28 records](../../logs/suspicious-network.jsonl): 24 blocked attempts
to ports 8000–8023 on `198.51.100.20`, and four allowed browser connections to
`203.0.113.10:443`. Documentation addresses are not actual targets or threat intel.

## Detection

Run [suspicious-network.spl](../../detections/suspicious-network.spl), All time:

```spl
index=soc_lab sourcetype="soc:json" event_type="network_connection"
| dedup event_uid
| bin _time span=1m
| stats count AS attempts dc(dest_port) AS distinct_ports values(dest_port) AS ports values(result) AS outcomes values(event_uid) AS evidence BY _time hostname username src_ip dest_ip protocol
| where attempts >= 20 AND distinct_ports >= 10
| sort _time
```

- `event_type` selects connections, and `event_uid` removes replay duplicates.
- `_time` is bucketed into a fixed minute. `hostname`, `username`, `src_ip`,
  `dest_ip`, and `protocol` prevent unrelated identities/destinations/protocols
  from being combined.
- `dest_port` is an integer. `dc` counts unique ports, `values` retains their list.
- `attempts` counts both allowed and blocked records; `outcomes` exposes the
  source `result`. A count is not the number of successful sessions.
- `evidence` retains raw event references. Threshold: **20 attempts AND 10 unique
  ports in one minute**. Both conditions must hold.

Expected: **one row**, 24 attempts, 24 ports, blocked, 10:30:00 UTC bucket,
`linux-client-01`, `casey`, `192.0.2.60` → `198.51.100.20`, TCP.

## Triage and correlation

```spl
index=soc_lab sourcetype="soc:json" hostname="linux-client-01" src_ip="192.0.2.60"
| dedup event_uid
| sort 0 _time
| table _time event_uid username dest_ip dest_port protocol process process_guid result
```

1. Identify two-second spacing over 46 seconds and sequential destination ports.
2. Correlate suspicious attempts by `lab-scan-001` / `python3`; this attribution
   is synthetic endpoint enrichment. Ask for actual process command line and
   parent in a real environment; they are not present in these network events.
3. Keep the four allowed browser connections separate by destination and process.
   They are not evidence that the 24 suspect connections succeeded.
4. Hypothesize service probing; consider an authorized inventory/vulnerability
   scanner. Approval context is absent, so intent is unresolved.
5. Assign MEDIUM: suspicious pattern, single source/destination, all blocked,
   no evidence of transferred data. Escalate to validate process ownership and
   authorization if the activity cannot promptly be explained.
6. Recommend preserving host/firewall evidence, maintaining the block, reviewing
   the script and scheduled tasks, and stopping the process only if unauthorized.

## False positives, tuning, and evasion

Approved scanners, service health checks, and misconfigured retry loops can
produce bursts. Tune by verified scanner identity, destinations, ports, and
maintenance window. Rate alone should not be a malware verdict. Slow scans,
distributed sources, many destinations with few ports each, or minute-boundary
splitting evade this vertical-scan rule. One-port beaconing is outside its scope.

## Complete workflow

Simulated connections → JSONL → Splunk → frequency/port finding → endpoint triage
→ collect network IDs → correlate process/outcomes → service-probing hypothesis
→ consider approved scans → suspicious unresolved activity → MEDIUM → contextual
escalation → conditional process containment → [incident 004](../../investigations/incident-004.md).

Mapping: [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/),
as a scanning-like behavioral hypothesis. No successful discovery is established.
