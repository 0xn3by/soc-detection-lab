# 02 — Suspicious PowerShell arguments

## Objective and source

Identify encoded-command or execution-policy-bypass arguments in PowerShell
process creation. Input is normalized synthetic Sysmon-like and PowerShell
script-block telemetry; Windows is not required.

```bash
python3 scripts/generate_events.py --scenario suspicious-powershell
```

Inspect [the three records](../../logs/suspicious-powershell.jsonl). A synthetic
`winword.exe` parent launches PowerShell with suspicious switches. Its encoded
payload is only `Write-Output 'SOC LAB ONLY'`; no command is executed. A second
ordinary inventory-script launch is a negative control.

## Detection

Run [suspicious-powershell.spl](../../detections/suspicious-powershell.spl), All time:

```spl
index=soc_lab sourcetype="soc:json" event_type="process_start"
| dedup event_uid
| where in(lower(process), "powershell.exe", "pwsh.exe")
| where match(command_line, "(?i)-(enc|encodedcommand)\\b") OR match(command_line, "(?i)-executionpolicy\\s+bypass\\b")
| table _time event_uid hostname username process parent_process process_guid command_line
| sort _time
```

- `event_type` limits the search to process starts; `event_uid` prevents replay
  duplicates. `process` contains a normalized basename. `lower` handles case.
- `command_line` is evaluated case-insensitively (`(?i)`). `\\b` is a regex word
  boundary and `\\s+` whitespace after SPL string escaping. It matches `-enc` or
  `-EncodedCommand`, or `-ExecutionPolicy Bypass`.
- `parent_process` adds context but is not required by the detection. `_time`,
  `hostname`, and `username` establish when, where, and who. `process_guid` is
  a correlation field for this fixture.
- Threshold: **one matching process event**; no aggregate window required.

Expected: **one row**, `suspicious-powershell-001`, 10:10:00 UTC,
`win-workstation-01`, `LAB\jordan`, parent `winword.exe`.

## Triage and correlation

```spl
index=soc_lab sourcetype="soc:json" hostname="win-workstation-01" process_guid="lab-ps-001"
| dedup event_uid
| sort 0 _time
| table _time event_uid event_type username parent_process command_line script_text
```

1. Inspect the full command and the unusual Office parent. Confirm process start
   does not establish malicious payload execution.
2. Decode the Base64 as UTF-16LE **as text only**:

```bash
python3 -c 'import base64,json; e=json.loads(open("logs/suspicious-powershell.jsonl").readline()); print(base64.b64decode(e["command_line"].split()[-1]).decode("utf-16le"))'
```

3. Correlate `suspicious-powershell-002` at 10:10:01; its script text agrees with
   the decoded content. Shared ProcessGuid is lab enrichment, not a native 4104
   field. Read [schema caveats](../../docs/event-schema.md).
4. For this known exercise, classify as benign simulation: LOW, no escalation.
   For an unknown real case, benign decoded content alone is insufficient to
   explain Word's involvement; inspect the document, full process tree, other
   script blocks, network activity, and user intent before closure.
5. Record the disposition and preserve the rule. Do not suppress all encoded
   PowerShell just because this one payload is harmless.

## False positives, tuning, and evasion

Management agents, installers, and administrators may use encoded arguments or
bypass for legitimate scripts. Execution policy is not a malware verdict. Tune
with a verified script identity, parent, owner, host scope, and expiry. Shortened
switches other than `-enc`, unusual whitespace/quoting, obfuscation, renamed
executables, or execution through another host can evade this simple rule.
Native paths must be normalized before using it on real Sysmon logs.

## Complete workflow

Simulated process → JSONL → Splunk input → indicator finding → process triage →
collect process/script records → correlate/decode → suspicious-execution hypothesis
→ verify harmless exercise explanation → benign positive → LOW → no escalation
→ document and retain detection → [incident 002](../../investigations/incident-002.md).

Behavior mapping: [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/).
The tool/technique mapping is not a maliciousness verdict.
