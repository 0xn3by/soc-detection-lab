#!/usr/bin/env python3
"""Create an evidence-populated incident draft; leave analyst decisions explicit."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from analyze_events import detect
from generate_events import SCENARIOS

ROOT = Path(__file__).resolve().parents[1]
TITLES = {
    'brute-force': 'Authentication failures and follow-up login review',
    'suspicious-powershell': 'Suspicious PowerShell argument review',
    'admin-account-creation': 'Local administrator membership review',
    'suspicious-network': 'Scanning-like network activity review',
}


def render_report(scenario, incident_id, logs_dir):
    path = logs_dir / f'{scenario}.jsonl'
    raw = path.read_bytes()
    events = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    if not events or any(e.get('scenario') != scenario for e in events):
        raise ValueError('Expected nonempty records for the selected scenario')
    if len({e['event_uid'] for e in events}) != len(events):
        raise ValueError('Duplicate event IDs in report source; resolve before reporting')
    def values(field):
        return ', '.join(sorted({str(e[field]) for e in events if field in e})) or 'Not supplied'
    timeline = []
    for e in sorted(events, key=lambda item: (item['timestamp'], item['event_uid'])):
        detail = '; '.join(f'{k}={e[k]}' for k in (
            'hostname', 'username', 'src_ip', 'dest_ip', 'dest_port',
            'process', 'actor', 'target_user', 'group_name') if k in e)
        timeline.append(f"- {e['timestamp']} — `{e['event_uid']}` — {e['event_type']} / {e['result']}; {detail}")
    findings = json.dumps(detect(events), indent=2)
    fields = {
        'INCIDENT_ID': incident_id, 'TITLE': TITLES[scenario], 'SCENARIO': scenario,
        'HOSTS': values('hostname'),
        'USERS': f"Observed users: {values('username')}\n\nActors: {values('actor')}\n\nTarget accounts: {values('target_user')}",
        'SOURCES': values('src_ip'),
        'EVIDENCE': f"Source: `{path.resolve()}` ({len(events)} events, including controls).\n\nSHA-256: `{hashlib.sha256(raw).hexdigest()}`\n\nOffline reference findings (not Splunk results):\n\n```json\n{findings}\n```",
        'TIMELINE': '\n'.join(timeline),
    }
    template = (ROOT/'reports'/'incident-report-template.md').read_text()
    for key, value in fields.items():
        template = template.replace('{{'+key+'}}', value)
    return template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', required=True, choices=SCENARIOS)
    parser.add_argument('--incident-id', required=True)
    parser.add_argument('--logs-dir', type=Path, default=ROOT/'logs')
    parser.add_argument('--output', type=Path, required=True, help='New Markdown file; never overwrite existing work')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.incident_id):
        parser.error('Incident ID must contain only letters, digits, hyphens, and underscores')
    try:
        report = render_report(args.scenario, args.incident_id, args.logs_dir)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as output:
            output.write(report)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Report not created: {error}\n')
    print(f'Created {args.output}; complete the analyst decision sections before use.')


if __name__ == '__main__':
    main()
