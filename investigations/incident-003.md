# Incident 003 — Unexplained creation of a local administrator

> Fictional exercise using synthetic Windows-like audit records. No account or
> privilege was changed on the host. Live Splunk execution remains pending.

## 1. Incident ID

LAB-003

## 2. Incident title

New account `lab_backup` added to local Administrators.

## 3. Detection source

[Admin membership SPL](../detections/admin-account-creation.spl), successful
group change in `soc_lab` / `soc:json`; modeled events 4732, 4720, and Sysmon 1.

## 4. Detection timestamp

Not recorded; add actual replay search/alert timestamp and job ID.
Matched event time: **2026-01-15 10:20:10 UTC**.

## 5. Affected host

`win-server-01`; actual business role/criticality is not supplied.

## 6. Affected user

Target account `lab_backup`; initiating actor `LAB\helpdesk`. These are distinct
roles, and the actor's authority to make this change is unknown.

## 7. Source IP

Not supplied by the fixture. The initiating account is not an IP attribution.

## 8. Summary

The audit sequence shows account creation, then successful assignment to local
Administrators eight seconds later. A nearby `net.exe` process names the same
target. Classification: **unexplained privileged change / suspected unauthorized
account provisioning**, unresolved. Confidence is high in the modeled change,
but authorization and intent cannot be determined from available evidence.

## 9. Evidence

Source: [admin-account-creation.jsonl](../logs/admin-account-creation.jsonl).

- `admin-account-creation-001`: `LAB\helpdesk`, `net.exe`, `cmd.exe` parent,
  command `net user lab_backup /add`; supports account-creation context.
- `admin-account-creation-002`: account creation success (4720), target
  `lab_backup`, actor `LAB\helpdesk`, logon label `0xLAB42`.
- `admin-account-creation-003`: membership success (4732), same actor/target/
  logon label, group SID `S-1-5-32-544` (Administrators); the actual detection match.
- `admin-account-creation-004`: different actor adds `lab_reader` to ordinary
  Users (`S-1-5-32-545`); not a privileged finding.

## 10. Timeline

All times are 2026-01-15 UTC:

- 10:20:00 — nearby `net.exe` start (001).
- 10:20:02 — target account created (002).
- 10:20:10 — local Administrators membership granted (003).
- 10:20:30 — independent Users-group change (004).

## 11. Investigation process

Validate the group SID, successful result, actor, and target. Use the [scenario
pivot](../scenarios/03-admin-account-creation/README.md) to collect creation and
membership events; correlate host/actor/target/logon label. Treat the nearby
process as supporting association, not proof it caused the audit event. In a
real case, check the change request, actor entitlement, account owner, logon
source, and subsequent target logins. Those records are not supplied here.

## 12. Analyst observations

This is local administration, not a domain administrator grant. Local privileges
could support persistence and credential access, but no later abuse is observed.
There is no approval ticket in the dataset; that is a context gap, not proof
that approval was denied or absent in reality.

## 13. False-positive possibilities

Approved backup-account provisioning, emergency support, or a sanctioned local
administrator rollout. Verify documented authorization before reversing a change.

## 14. Severity

**HIGH** (provisional).

## 15. Severity justification

A successful privileged change creates substantial potential impact even while
intent is unresolved. Scope is one host and one new account; there is no evidence
of data access, lateral movement, or widespread compromise to justify CRITICAL.

## 16. Escalation required

**Yes — recommended to a senior analyst and system owner; no contact was made.**

## 17. Escalation justification

Authorization cannot be validated locally and the added privilege is effective
in the modeled telemetry. Request approval verification, subsequent-use review,
and a decision on removing membership if not authorized.

## 18. Recommended remediation

Preserve audit events and current membership evidence. Confirm ownership and
approval. If unauthorized, disable the new account/remove membership under
authorization, review actor sessions and credential exposure, and inspect other
hosts for related changes. Improve least-privilege provisioning and auditing.
These are recommendations; no changes were applied.

## 19. Lessons learned

Privilege assignment is more consequential than account creation alone. SIDs
make the rule less dependent on localized group names; approval context still
requires human investigation and cannot be inferred from event 4732.

## 20. MITRE ATT&CK mapping

[T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) and
[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
describe the modeled sequence if adversarial. Mapping does not prove intent.
