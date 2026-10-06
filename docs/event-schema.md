# Event schema

All records are one JSON object per line, UTF-8. Every record includes:

- `timestamp`: ISO 8601 UTC event time. Splunk parses this into `_time`.
- `event_uid`: stable unique fixture identifier; reused on deterministic replay.
- `scenario`: exercise grouping for navigation, never a detection criterion.
- `synthetic`: boolean `true`, declaring provenance, never a detection criterion.
- `hostname`: simulated endpoint; distinct from Splunk's input metadata `host`.
- `username`: account associated with the activity. On account changes it is the
  initiating user, not the account receiving privileges.
- `event_type`: normalized activity category.
- `result`: `failure`, `success`, `observed`, `blocked`, or `allowed`, interpreted
  according to the event type; process-start success is not attack success.
- `log_source`: modeled data source, not evidence of a real collector.

## Type-specific fields

Authentication has `src_ip`, `process=sshd`, `auth_method=password`, and
`event_type=authentication`. These are Linux auth-like normalized records, not
literal `/var/log/secure` lines. They preserve the investigation facts that SSH
logs normally provide without exposing real account or host data.

Process start has `event_id=1`, `process`, `parent_process`, `command_line`, and
`process_guid`. PowerShell process events also include `parent_guid`.
`event_id=1` represents Sysmon process creation semantics. Paths are simplified
to executable basenames. A real Sysmon pipeline would normalize full Image paths.

PowerShell script blocks use `event_id=4104`, `script_text`, and `process_guid`.
**The shared process GUID is synthetic enrichment**: a native 4104 record does
not supply a Sysmon ProcessGuid. Real correlation requires host, process ID,
time, and sometimes session data; PID reuse must be handled.

Account creation uses `event_id=4720`, `actor`, `target_user`, and `logon_id`.
Group membership changes use `event_id=4732` plus `group_name` and `group_sid`.
`S-1-5-32-544` is the built-in local Administrators group. The GUID/logon markers
beginning `lab-` / `0xLAB` are readable synthetic correlation labels, not native
Windows identifiers. Account creation and group membership share a logon label;
the nearby `net.exe` event is associated by host, user, target name, and time only.

Network records have `src_ip`, `dest_ip`, integer `dest_port`, `protocol`,
`process`, and `process_guid`. Process/user attribution represents endpoint
enrichment; many network firewalls alone cannot supply it. A blocked record shows
an attempted connection, not a completed TCP handshake or transferred data.

Addresses use documentation networks (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). They are placeholders, not reputation indicators. No geolocation,
DNS, byte count, asset inventory, change approval, or actual business impact is
present. Do not invent those facts when investigating.

Splunk adds `_raw`, `_time`, `_indextime`, `index`, `source`, `sourcetype`, and
`host`. Counts such as `failed_attempts`, `attempts`, and `distinct_ports` are
derived by SPL rather than expected in the JSON. All timestamps are fixed on
2026-01-15; search All time and display UTC.
