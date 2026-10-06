# {{INCIDENT_ID}} — {{TITLE}}

> Personal security lab / synthetic evidence. Draft; analyst review required.
> Offline reference findings are not Splunk execution evidence. No real incident,
> escalation, or remediation is implied by this document.

## 1. Incident ID

{{INCIDENT_ID}}

## 2. Incident title

{{TITLE}}

## 3. Detection source

Proposed Splunk search: `detections/{{SCENARIO}}.spl`, index `soc_lab`, sourcetype
`soc:json`. Record actual search text, time range, job ID, and exported result.

## 4. Detection timestamp

Not recorded. Enter actual UTC search/alert execution time. Do not substitute
the event timestamp or aggregation bucket start.

## 5. Affected host

{{HOSTS}}

## 6. Affected user

{{USERS}}

Distinguish actor from target account and exclude unrelated comparison events.

## 7. Source IP

{{SOURCES}}

## 8. Summary

[Analyst: state observed behavior, hypothesis, scope, classification/disposition,
confidence, and what remains unknown. Do not automatically equate a match with compromise.]

## 9. Evidence

{{EVIDENCE}}

Preserve raw evidence and a copy of the query result. Record which IDs support
each conclusion. The file hash detects fixture changes; it is not a full forensic
chain of custody or proof of authenticity.

## 10. Timeline

{{TIMELINE}}

## 11. Investigation process

[Analyst: document validation, pivots, correlations, additional context checked,
and the reason for the final disposition. Mark proposed checks as proposed.]

## 12. Analyst observations

[Separate direct facts from inference; identify missing data and attribution limits.]

## 13. False-positive possibilities

[List plausible legitimate explanations and the evidence needed to validate them.]

## 14. Severity

[LOW / MEDIUM / HIGH / CRITICAL — analyst decision required.]

## 15. Severity justification

[Confidence, success, asset role, privilege, scope, potential impact, observed impact.]

## 16. Escalation required

[Yes / No — analyst decision required. Distinguish recommended from actually sent.]

## 17. Escalation justification

[Who should receive the handoff, why, urgency, outstanding question, requested action.]

## 18. Recommended remediation

[Preservation, proportionate containment, recovery, hardening. Record authorization
and completed actions separately from recommendations.]

## 19. Lessons learned

[Detection tuning, evidence gaps, and what would improve future investigation.]

## 20. MITRE ATT&CK mapping

[Technique/sub-technique and primary reference, with behavioral justification;
use “not established” where evidence does not support a mapping.]
