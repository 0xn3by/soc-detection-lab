# Junior SOC triage playbook

## When an alert fires

1. **What happened?** Read the rule, matching raw events, count, and time window.
   Confirm parsing and exclude duplicate-ingestion artifacts.
2. **Which host?** Use `hostname`; establish host role/owner if available. Never
   infer business criticality solely from a hostname.
3. **Which user?** Identify the acting account and affected account separately.
   For privileged changes, inspect `actor` and `target_user`.
4. **Which source?** Record `src_ip` when present; NAT and shared hosts weaken
   attribution. If absent, say unavailable rather than guessing.
5. **What time?** Record UTC event times, search range, and actual detection time.
   A bucket timestamp is not when Splunk fired the alert.
6. **Was it successful?** Distinguish failed login, successful login, successful
   process creation, successful privilege change, and blocked connection.
7. **Immediately before?** Expand at least five minutes before the match; look
   for related process starts, authentication, and account changes.
8. **Immediately after?** Look for logins, new children, added persistence,
   outbound traffic, and additional privilege changes. Missing logs are not proof
   that none occurred.
9. **Related events?** Correlate host + identity + time, then process/session IDs
   where valid. Keep a timeline of event IDs and mark uncertain relationships.
10. **Could it be legitimate?** Check user error, maintenance, deployment scripts,
    approved account provisioning, and authorized scans. Verify approvals with
    an owner in a real investigation; no real tickets exist in this exercise.
11. **Likely impact?** Assess observed access, privilege, affected scope, possible
    persistence/lateral movement, and data access. Separate potential from proven.
12. **Severity?** Apply the model below, explaining confidence and impact.
13. **Escalate?** Route plausible compromise or unexplained privileged success to
    a senior analyst/IR lead. Provide a concrete question and recommended action.
14. **Remediation?** Recommend proportionate containment, recovery, and hardening.
    Preserve evidence first and obtain organizational authority before acting.

## Severity model

- **LOW:** benign or approved explanation supported by evidence; limited impact
  and no observed unauthorized access. Document and close or monitor.
- **MEDIUM:** credible suspicious activity with uncertain intent or blocked/
  unsuccessful behavior; limited observed scope. Seek owner context and escalate
  if unresolved or persistent.
- **HIGH:** plausible unauthorized successful access, unexplained successful
  administrative privilege change, or strong compromise evidence. Prompt senior
  analyst/IR review; scope and contain with authorization.
- **CRITICAL:** verified or strongly supported severe ongoing impact, such as
  widespread privileged compromise, destructive actions, or major sensitive-data
  access/exfiltration. Immediate incident coordination. None of these fixtures
  demonstrates such impact.

Confidence and impact are separate. Uncertain intent can still warrant HIGH
because local-admin capability substantially increases potential harm. A blocked
scan can warrant escalation without being HIGH. Suspicious syntax alone does not
justify CRITICAL. The asset's actual criticality and exposure matter when known.

## Classification and decisions in this lab

- Incident 001: suspected credential attack with a subsequent successful login;
  HIGH, escalate for possible unauthorized access.
- Incident 002: benign simulation after reviewing the harmless decoded content
  and known exercise provenance; LOW, no escalation. Unexplained Word → PowerShell
  on a real workstation would require further review before closure.
- Incident 003: unexplained new local administrator in the exercise; HIGH,
  escalate because privilege was actually granted in the modeled telemetry.
- Incident 004: suspected scanning-like activity, all suspicious attempts blocked;
  MEDIUM, escalate for owner/process authorization review, not emergency isolation.

These are analyst recommendations within a fictional exercise. No real escalation
messages, tickets, containment, or remediation have been performed.

## Handoff in under a minute

“I observed [behavior] on [host] by [actor] at [UTC time]. Evidence [IDs] shows
[outcome]. My hypothesis is [claim], with [confidence], because [facts]. I also
considered [benign alternatives]. Impact is [observed / potential]. I recommend
[severity] and [escalation/action]. We still need [specific evidence/context].”

Use the [report template](../reports/incident-report-template.md) to preserve all
20 required report fields. Record a disposition separately from the detection:
true positive, benign positive, false positive, or unresolved. A correct match on
an approved simulation can be a benign positive rather than a broken rule.
