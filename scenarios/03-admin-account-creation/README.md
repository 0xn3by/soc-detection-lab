# 03 — Newly created local administrator

## Objective and source

Detect a successful addition to the built-in local Administrators group, then
investigate whether the target account was newly created. Source records model
Windows Security events 4720/4732 plus a Sysmon-like process start.

```bash
python3 scripts/generate_events.py --scenario admin-account-creation
```

Inspect [the four records](../../logs/admin-account-creation.jsonl). They model
`net.exe`, creation of `lab_backup`, and addition to Administrators. A different
account added to ordinary Users is the negative control. No accounts are created.

## Detection

Run [admin-account-creation.spl](../../detections/admin-account-creation.spl), All time:

```spl
index=soc_lab sourcetype="soc:json" event_type="group_member_added" result="success" group_sid="S-1-5-32-544"
| dedup event_uid
| table _time event_uid hostname actor target_user group_name group_sid logon_id
| sort _time
```

- `event_type` and `result` require a completed membership change.
- `group_sid` selects local Administrators regardless of the displayed language
  of `group_name`; it does not cover every privileged/domain group.
- `actor` is the initiating identity, `target_user` receives privilege,
  `hostname` is the affected server, and `_time` is the event timestamp.
- `logon_id` supports linking related changes within the same host/session;
  do not join it globally across hosts. `event_uid` identifies raw evidence.
- Threshold: **one successful membership addition**. The rule catches additions
  to existing or new accounts; it does not require 4720 to match.

Expected: **one row**, `admin-account-creation-003`, 10:20:10 UTC,
`win-server-01`, actor `LAB\helpdesk`, target `lab_backup`, group Administrators.

## Triage and correlation

```spl
index=soc_lab sourcetype="soc:json" hostname="win-server-01" target_user="lab_backup"
| dedup event_uid
| sort 0 _time
| table _time event_uid event_id event_type username actor target_user logon_id process parent_process command_line group_name result
```

1. Confirm success, the receiving account, and SID rather than relying on title.
2. Link the creation at 10:20:02 to membership at 10:20:10 using target, actor,
   host, and `0xLAB42`. See the nearby `net.exe` start at 10:20:00.
3. The process association is temporal support, not definitive causation: this
   fixture does not include a process/session join for the audit records.
4. An approval ticket and helpdesk authorization are **not supplied**. Determine
   whether expected by checking an owner/change record in a real investigation;
   here expectedness stays unresolved. Do not turn missing approval data into
   proof of unauthorized activity.
5. Assign HIGH and escalate for validation of an unexplained privileged change.
   Local administration can enable persistence, credential access, and wider
   compromise; none of those downstream actions is observed here.
6. Recommend preserving logs and confirming authorization, then disabling the
   account/removing membership if unauthorized and reviewing the actor's access.

## False positives, tuning, and evasion

Approved provisioning, emergency access, and support tooling can legitimately
add administrators. Tune by change window and verified provisioning context, not
by suppressing every helpdesk user. Use explicit group SIDs for additional groups
only when needed. Domain group changes, non-Windows privilege mechanisms, direct
permission assignments, already privileged accounts, and audit loss are outside
this rule. A standalone account-created event without privilege change does not
trigger this detection.

## Complete workflow

Simulated account/group change → JSONL → Splunk → membership finding → actor/target
triage → collect 001–003 → correlate creation → unauthorized-admin hypothesis →
consider provisioning → unresolved privileged-change incident → HIGH → escalation
recommended → conditional privilege removal → [incident 003](../../investigations/incident-003.md).

Mappings: [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/)
and [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/).
These describe the modeled behavior; no adversary intent is established.
