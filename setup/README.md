# Start the SOC lab

Run all commands from the repository root. The Python tools need only Python 3.10+
and its standard library. Splunk needs Docker Engine and the Compose plugin.

1. Generate fixtures: `python3 scripts/generate_events.py`.
2. Run checks: `python3 -m unittest discover -s tests -v`.
3. Follow [Splunk startup](splunk-setup.md) to configure credentials and start it.
4. Follow [ingestion and search verification](log-ingestion.md).
5. Open each [scenario](../scenarios/01-brute-force/README.md), run its detection,
   and compare the evidence with the worked investigation.

All data is fictional. Windows records are normalized synthetic telemetry, not
native EVTX or live Windows collection. Linux records represent SSH authentication
and endpoint-enriched firewall activity; they are not collected from this host.

## One-day order

- First hour: Python checks, Docker startup, ingestion, timestamp verification.
- Second hour: brute-force search, success correlation, first screenshot.
- Third hour: PowerShell, account privilege, and network investigations.
- Fourth hour: report review, screenshot capture, interview rehearsal.
- Reserve remaining time for ingestion troubleshooting. The dashboard is optional.

Live validation is recorded separately in [validation](../docs/VALIDATION.md).
Passing offline checks does not prove that SPL executed successfully in Splunk.
