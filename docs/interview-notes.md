# Interview notes — explain the lab in your own words

## Explain your SOC lab

“I built a personal Splunk investigation lab around four synthetic scenarios:
SSH failures, suspicious PowerShell arguments, a local administrator change,
and scanning-like connections. I wrote deterministic Python generators and SPL
rules, then documented evidence, competing explanations, severity, and escalation
for each. It is a lab, not production SOC employment.” Add what you actually
verified in Splunk after completing the live checklist; until then say execution
is pending rather than claiming you operated a live SIEM pipeline.

## How did your logs reach Splunk?

“The configured path is a read-only bind mount into a single Splunk container.
A file monitor tags each JSON line with `soc:json` and sends it to `soc_lab`.
Timestamp parsing sets `_time`; search-time JSON extraction supplies fields.
There is no forwarder or HEC token in this version.” Say “I verified arrival”
only after observing the expected 47 unique events in Splunk.

## What is a SIEM?

A security information and event management platform centralizes logs, makes
them searchable, and supports correlation, detection, and investigation. Its
alerts need analyst context; a SIEM match is not automatically an incident.

## How did you detect brute force?

I selected failed authentication events, deduplicated fixture IDs, grouped by
source, endpoint, user, and a five-minute bucket, and required at least five
failures. The fixture has eight. I separately investigated the subsequent login
success rather than claiming the failure rule itself proves compromise.

## Why did you choose that threshold?

Five in five minutes gives a clear demonstration with a two-failure negative
control. It is an explainable lab setting, not a tuned enterprise baseline.
Real thresholds need historical volume, account/asset context, and false-positive
review. Fixed bucket boundaries can miss a burst spanning two buckets.

## What could cause a false positive?

A user repeatedly mistyping a password or an automation job using a stale secret.
For other rules: approved encoded scripts, authorized admin provisioning, or
sanctioned scans. I would verify the owner, change record, purpose, and scope,
then add a narrow documented exception rather than suppress the entire behavior.

## How would you investigate suspicious PowerShell?

Inspect host, user, parent, full arguments, process/session context, script logs,
and subsequent connections or child processes. Decode Base64 as UTF-16LE text
without executing it. In this fixture the script prints a harmless lab marker;
known simulation provenance supports closure. In a real Word → PowerShell case,
one harmless script block would not be enough to rule out compromise.

## What is the difference between an alert and an incident?

An alert is a rule match needing review. An incident is an assessed security
event or suspected harmful activity requiring coordinated handling. Triage may
close an alert as benign or keep it unresolved pending context. My PowerShell
case is a benign positive, while other cases warrant further investigation.

## How do you determine severity?

I separate confidence from impact and assess success, privilege, asset importance,
scope, persistence/lateral movement potential, and data access. An unexplained
successful administrator grant is HIGH even if intent is uncertain. All-blocked
probing is MEDIUM here; none of the fixtures proves CRITICAL impact.

## When would you escalate?

When successful access or privileged change could be unauthorized, when scope
exceeds my authority, or when missing context makes safe closure impossible.
I hand off facts, evidence IDs, hypothesis, severity rationale, and a specific
request. My escalation decisions are recommendations in an exercise, not real
tickets or messages sent to an organization.

## How did you investigate account creation?

The detector identifies the successful Administrators membership by SID. I
correlated it with the preceding account creation using host, actor, target,
and logon label. The nearby `net.exe` start is supporting evidence, not a proven
process-to-audit join. Missing approval records mean authorization is unknown.

## How did you investigate the network alert?

I counted both attempts and unique ports for each source/destination in one
minute. The 24 sequential ports and regular timing suggest probing; all were
blocked. I separated four allowed browser events to another destination and
would request the actual script and approval context before deciding intent.

## What would change in a real enterprise environment?

Deploy authorized collectors, normalize native formats, handle time synchronization
and delivery delay, enforce access/retention policy, enrich with asset/identity
context, and integrate case handling. Validate alert scheduling, noise, escalation
ownership, and authorized response. Do not assume this single-node lab solves
scale, resilient collection, or operational incident response.

## What limitations exist in this lab?

All data is synthetic and small; there are no real endpoint agents, native EVTX
parsers, threat-intelligence sources, enterprise baselines, or real incidents.
Some process/session context is synthesized. Simple fixed buckets and argument
matches miss evasions. Offline tests verify intended fixture logic, not Splunk's
execution engine. State the live validation status honestly.

## How would EDR improve the investigation?

It could add reliable process trees, executable hashes/signatures, process-to-network
links, session context, and response actions. That would help attribute the scan
and investigate the Word parent. EDR adds evidence; it does not eliminate the
need for authorization context or analyst judgment.

## How would you tune detections?

Measure normal activity by role, sample matched and missed behavior, test threshold
boundaries, and validate narrow exceptions with owners. Improve window handling,
PowerShell normalization, and privileged-group coverage. Document each tradeoff
and retest the original positives and benign controls.

## What did you personally implement and test?

Python log generation, fixture analysis, report drafting, Splunk input/index/
parsing configuration, four SPL searches, a simple event dashboard, and four
worked investigations. Cite [validation](validation.md) for actual executed checks.
Do not claim measured detection accuracy or production response-time improvements.

## Five-minute demonstration

Show the architecture briefly, verify event counts, run the brute-force search,
pivot to the success, explain HIGH/escalation, then contrast the benign PowerShell
case. End by explaining one blind spot and where the evidence stops.
