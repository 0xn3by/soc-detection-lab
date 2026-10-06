# Incident 004 — Blocked sequential-port connection burst

> Synthetic lab evidence only. No scan or external connection was executed.
> Live Splunk search verification and actual alert timestamp are pending.

## 1. Incident ID

LAB-004

## 2. Incident title

Scanning-like outbound activity from a modeled Python process.

## 3. Detection source

[Network SPL](../detections/suspicious-network.spl), synthetic endpoint-enriched
firewall records in `soc_lab` / `soc:json`.

## 4. Detection timestamp

Not recorded; add actual replay search time and job ID. Matching bucket starts
**2026-01-15 10:30:00 UTC** and is not the alert execution time.

## 5. Affected host

Source endpoint `linux-client-01`. The destination represents a fictional peer.

## 6. Affected user

`casey`, supplied as synthetic endpoint enrichment. No privilege data is provided.

## 7. Source IP

`192.0.2.60`; suspicious destination `198.51.100.20`. Both are documentation addresses.

## 8. Summary

Twenty-four blocked TCP attempts address 24 consecutive ports on one destination
within 46 seconds. Classification: **suspected service probing, authorization
unresolved**. Confidence is high in the scanning-like pattern and lower in
malicious intent. No successful connection or exfiltration is established.

## 9. Evidence

Source: [suspicious-network.jsonl](../logs/suspicious-network.jsonl).

- `suspicious-network-001`–`024`: `python3`, process GUID `lab-scan-001`,
  destination `198.51.100.20`, ports 8000–8023, TCP, all `blocked`.
- `suspicious-network-025`–`028`: `browser`, process GUID `lab-browser-001`,
  destination `203.0.113.10:443`, all `allowed`; separate benign control.

## 10. Timeline

All times are 2026-01-15 UTC:

- 10:30:00 — first blocked attempt, port 8000 (001).
- 10:30:02–10:30:46 — one blocked attempt every two seconds through port 8023
  (002–024). One fixed minute contains the entire burst.
- 10:30:00 / :10 / :20 / :30 — four unrelated allowed HTTPS-like browser records
  (025–028). Port 443 alone does not prove application-layer HTTPS.

## 11. Investigation process

Count unique ports and total attempts; verify consistent source/destination,
protocol, and outcomes. Use the [scenario timeline](../scenarios/04-suspicious-network-activity/README.md)
to compare the browser control. Pivot on the enriched process GUID and ask for
actual process command line, parent, script, scheduled job, and scan authorization
in a real environment. Those fields and approval records are not supplied.

## 12. Analyst observations

Sequential ports and regular frequency support a probing hypothesis. `blocked`
records do not establish open ports, handshakes, or bytes transferred. The allowed
browser records are to another destination and are not evidence of scan success.
The process attribution is modeled enrichment, not a native firewall guarantee.

## 13. False-positive possibilities

Authorized vulnerability scanning, inventory tooling, or a misconfigured service
check. Neither malicious intent nor approval can be concluded from frequency alone.

## 14. Severity

**MEDIUM**.

## 15. Severity justification

The activity is suspicious and attributable within the synthetic dataset, but
limited to one source/destination and all suspect attempts are blocked. There
is no persistence, successful access, or measured business impact.

## 16. Escalation required

**Yes — contextual review recommended, not emergency containment.** No message
or ticket has been sent.

## 17. Escalation justification

The endpoint owner/senior analyst should validate script ownership and scan
authorization. Repeated or unexplained probing needs follow-up even when blocked.
Provide the time range, process attribution caveat, ports, and blocked outcome.

## 18. Recommended remediation

Preserve network and endpoint evidence, retain the existing block, review the
script/scheduled tasks, and stop unauthorized activity with owner approval.
If approved, document a narrow time-bounded scanner exception. Do not claim a
need to reset credentials or isolate a host solely from this blocked burst.

## 19. Lessons learned

Frequency plus port diversity gives a more useful signal than raw connection
volume alone. Outcome and authorization context control the severity decision.

## 20. MITRE ATT&CK mapping

[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
fits the probing hypothesis. No successful service discovery, command-and-control,
or exfiltration mapping is supported by this evidence.
