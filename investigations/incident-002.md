# Incident 002 — Encoded PowerShell, benign exercise disposition

> Personal lab with synthetic process telemetry. No PowerShell was executed.
> Live Splunk search verification is pending. The benign disposition relies on
> known fixture provenance and decoded text, not a claim about a real endpoint.

## 1. Incident ID

LAB-002

## 2. Incident title

Suspicious PowerShell switches with a harmless encoded command.

## 3. Detection source

[PowerShell SPL](../detections/suspicious-powershell.spl), synthetic normalized
Sysmon process-start event plus PowerShell script-block telemetry in `soc_lab`.

## 4. Detection timestamp

Not recorded; capture the actual search/alert time and job ID during live replay.
The matching event time is **2026-01-15 10:10:00 UTC**.

## 5. Affected host

`win-workstation-01` (fictional).

## 6. Affected user

`LAB\jordan`. The separate inventory process runs as `LAB\itadmin`.

## 7. Source IP

Not available in these process/script records; not inferred.

## 8. Summary

PowerShell uses `-EncodedCommand` and `-ExecutionPolicy Bypass`, with `winword.exe`
as its modeled parent. The payload decodes to `Write-Output 'SOC LAB ONLY'`,
matching the next script-block record. Classification: **benign positive / known
simulation**, closed for this exercise. Confidence in the benign fixture is high.

## 9. Evidence

Source: [suspicious-powershell.jsonl](../logs/suspicious-powershell.jsonl).

- `suspicious-powershell-001`: process `powershell.exe`, parent `winword.exe`,
  process GUID `lab-ps-001`; full command line is preserved in JSON.
- `suspicious-powershell-002`: event 4104 representation, same enriched process
  GUID, `script_text="Write-Output 'SOC LAB ONLY'"`.
- `suspicious-powershell-003`: `powershell.exe -File C:\IT\inventory.ps1` from
  `explorer.exe`, another user; does not match the indicator rule.

## 10. Timeline

All times are 2026-01-15 UTC:

- 10:10:00 — modeled process start with encoded/bypass arguments (001).
- 10:10:01 — modeled script text corroborates harmless output command (002).
- 10:10:20 — separate ordinary inventory-script process (003).

## 11. Investigation process

Inspect parent, process, user, and full command line. Decode Base64 as UTF-16LE
text with the [safe scenario command](../scenarios/02-suspicious-powershell/README.md).
Do not evaluate the decoded text. Correlate the modeled script block, inspect
the generator's provenance, compare the control, and document why the behavioral
match is not malicious in this known exercise.

## 12. Analyst observations

Word spawning encoded PowerShell deserves scrutiny. Here the source generator
and matching harmless script establish the benign simulation. The shared 4104
process GUID is synthetic enrichment, not a native Windows field. In a real
case, obtain the document, complete process tree, other script blocks, user
confirmation, and network events; this small excerpt would not justify closure.

## 13. False-positive possibilities

Approved deployment tools and support scripts use encoded or bypass switches.
Unusual arguments are indicators, not proof of a malicious script. A signed
binary also does not establish benign intent.

## 14. Severity

**LOW** after analysis; initial triage priority would be MEDIUM pending context.

## 15. Severity justification

Known synthetic provenance and corroborated harmless script reduce concern in
this exercise. There is no modeled download, persistence, child payload, or data
access. Do not generalize the disposition to unexplained real Word launches.

## 16. Escalation required

**No — close as a documented benign simulation.**

## 17. Escalation justification

The fixture's suspicious syntax is fully explained by its documented exercise
purpose. Unverified provenance or additional suspicious behavior in a real case
would reopen triage and warrant senior review.

## 18. Recommended remediation

No containment is needed for the fixture. Retain process and script-block
visibility, record the benign disposition, and tune only verified narrow
automation patterns. Do not disable detection of all encoded PowerShell.

## 19. Lessons learned

Safe decoding and contextual evidence can resolve an alert. A correct behavioral
match can be benign; this is not automatically a rule false positive.

## 20. MITRE ATT&CK mapping

[T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) as a
behavioral mapping. Encoding alone does not justify claiming malware or obfuscated
malicious files. No actual technique execution occurred on the host.
