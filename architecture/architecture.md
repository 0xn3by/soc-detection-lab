# Architecture and trust boundaries

```text
Endpoint / Event Generator (fictional Linux + Windows activity)
          │ Python writes data only; no commands are executed
          ▼
       Log Files (four JSONL fixtures, 47 events, fixed UTC timestamps)
          │ read-only Docker bind mount /lab/logs
          ▼
       Splunk (one container: input + indexer + search head)
          │ index=soc_lab, sourcetype=soc:json
          ▼
   Detection Searches (four SPL files)
          │ search finding / optional saved alert
          ▼
         Alert
          ▼
        Triage (identity, host, outcome, adjacent events)
          ▼
 Investigation / Correlation (evidence IDs + explicit hypotheses)
          ▼
 Severity + Escalation (analyst decisions, not generator labels)
          ▼
    Incident Report (worked case + repeatable Markdown draft)
```

The Fedora host runs Python and Docker. No real endpoint agent is installed.
Windows and Linux source names describe normalized source semantics only.
The optional offline analyzer mirrors the rule logic to validate fixtures; it
does not ingest into Splunk, execute SPL, or replace the SIEM.

One Splunk instance keeps a one-day build practical. Splunk uses persistent named
volumes and two read-only input/configuration mounts. Only Web port 8000 is
published, bound to `127.0.0.1`; management and HEC ports stay unpublished.
Docker image download is the only required external data transfer. Synthetic
IP addresses come from documentation ranges and are never contacted.

Analyst context belongs in reports, not generated severity fields. The detector
does not use `scenario`, `synthetic`, expected-result labels, or hardcoded
attacker addresses to identify behavior. Its source fields are listed in each
scenario guide. `event_uid` supports fixture replay deduplication and evidence
references. In a real deployment an attacker-controlled identifier must not be
trusted as the sole deduplication key.

## Deliberate boundaries

- No real SSH password guessing, account creation, PowerShell execution, or scans.
- No Enterprise Security, CIM acceleration, SOAR, EDR deployment, cloud account,
  threat-intelligence feed, or external notification integration.
- No automatic containment or claim of remediation performed.
- No native syslog/EVTX parser. Real collection requires source onboarding and
  normalization; the synthetic enrichment is described in [schema](../docs/event-schema.md).
- The four exercises are independent. Their adjacent timestamps do not establish
  a shared attacker or an attack chain.

For growth, add actual authorized endpoint collection and verify parsing before
adding more rules. Keep the four existing acceptance results reproducible first.
