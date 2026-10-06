# Incident 001 — Authentication burst followed by a successful login

> Personal lab, synthetic evidence. This is a worked investigation, not a real
> company incident. Live Splunk search execution and actual detection time are
> pending; the source records and offline finding have been inspected locally.

## 1. Incident ID

LAB-001

## 2. Incident title

Repeated SSH failures followed by successful password authentication.

## 3. Detection source

[Brute-force SPL](../detections/brute-force.spl), `soc_lab` / `soc:json`, modeled
Linux authentication. [Offline finding](../reports/offline-findings.json) is a
Python reference result, not an executed Splunk alert.

## 4. Detection timestamp

Not recorded: enter actual replay search/alert time and job ID after Splunk
verification. The matching bucket begins **2026-01-15 10:00:00 UTC**; this is
event time, not detection time.

## 5. Affected host

`linux-web-01`; real owner, criticality, and data exposure are unknown.

## 6. Affected user

`alex`. Account privilege is not supplied.

## 7. Source IP

`192.0.2.50` (documentation address). No reputation or ownership claim.

## 8. Summary

Eight password failures in 140 seconds cross the five-failure threshold, then a
successful login occurs 30 seconds after the last failure. Classification:
**suspected credential attack with possible unauthorized access**, unresolved
intent. Confidence is high in the observed sequence and moderate in the attack
hypothesis. The fixture does not prove that a password was guessed.

## 9. Evidence

Source: [brute-force.jsonl](../logs/brute-force.jsonl).

- `brute-force-001`–`008`: eight `sshd` password failures for the same host,
  user, and source; these IDs form the detection finding.
- `brute-force-009`: successful password login by the same identity/source.
- `brute-force-010`–`012`: `sam` from `192.0.2.20`, two failures then success;
  a separate low-volume control, not part of the suspicious group.

## 10. Timeline

All times are 2026-01-15 UTC:

- 10:00:00 — first `alex` failure (001).
- 10:00:20–10:02:20 — seven more failures every 20 seconds (002–008).
- 10:00:30, 10:00:50, 10:01:10 — independent `sam` control sequence (010–012).
- 10:02:50 — `alex` successful login from the same source (009).

## 11. Investigation process

Read raw records; validate grouping and count; run the documented detection in
Splunk during replay; pivot using host/user/source and sort by event time using
the [scenario correlation query](../scenarios/01-brute-force/README.md).
Separate the control identity, inspect success after failure, and request user
confirmation and post-login activity in a real case. Those requests have not
been made in this lab. Preserve query, job ID, raw export, and timeline.

## 12. Analyst observations

The sequence is consistent with guessing but also with a legitimate user finally
entering the right password. The successful event raises potential impact; there
are no shell/process logs, session records, or lateral movement evidence. Absence
of those datasets prevents a conclusion about what happened after login.

## 13. False-positive possibilities

User mistakes, a stale automation password followed by a corrected secret,
or multiple users behind a shared source. Validate rather than assume an attacker.

## 14. Severity

**HIGH** (provisional exercise assessment).

## 15. Severity justification

Plausible successful access following a concentrated failure burst warrants
prompt review. Scope is one host/account; privilege and impact are unknown.
No evidence supports CRITICAL or a confirmed compromise claim.

## 16. Escalation required

**Yes — recommended within the exercise; no message or ticket was sent.**

## 17. Escalation justification

A senior analyst/IR lead should validate session legitimacy and collect endpoint
evidence. Handoff: same source/user, eight failures, later success, unknown
post-login actions; ask whether the session should be revoked.

## 18. Recommended remediation

Preserve authentication/session logs. If unauthorized, revoke sessions, reset
the credential, and investigate the endpoint under the owner's containment
procedure. Restrict SSH exposure, prefer keys/MFA where supported, and add
rate limiting with availability considerations. No remediation was performed.

## 19. Lessons learned

A threshold creates a lead; correlation changes its urgency. Keep success
evidence outside the failure-only query and explain fixed-bucket blind spots.

## 20. MITRE ATT&CK mapping

[T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
describes the hypothesis. A successful login alone is insufficient to assert
adversarial valid-account use or any later technique.
