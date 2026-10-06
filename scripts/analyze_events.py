#!/usr/bin/env python3
"""Offline reference logic, not an SPL interpreter or live Splunk validation."""
import argparse
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def detect(events):
    unique = {e['event_uid']: e for e in events}
    auth, network, findings = defaultdict(list), defaultdict(list), []
    for e in unique.values():
        epoch = int(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')).timestamp())
        if e['event_type'] == 'authentication' and e['result'] == 'failure':
            auth[(epoch//300, e['hostname'], e['username'], e['src_ip'])].append(e)
        if e['event_type'] == 'network_connection':
            network[(epoch//60, e['hostname'], e['username'], e['src_ip'], e['dest_ip'], e['protocol'])].append(e)
        if e['event_type'] == 'process_start' and e.get('process', '').lower() in ('powershell.exe', 'pwsh.exe'):
            if re.search(r'-(enc|encodedcommand)\b|-executionpolicy\s+bypass\b', e.get('command_line', ''), re.I):
                findings.append({'detection': 'suspicious-powershell', 'evidence': [e['event_uid']]})
        if e['event_type'] == 'group_member_added' and e['result'] == 'success' and e.get('group_sid') == 'S-1-5-32-544':
            findings.append({'detection': 'admin-account-creation', 'evidence': [e['event_uid']]})
    for group in auth.values():
        if len(group) >= 5:
            findings.append({'detection': 'brute-force', 'failed_attempts': len(group), 'evidence': sorted(e['event_uid'] for e in group)})
    for group in network.values():
        ports = {e['dest_port'] for e in group}
        if len(group) >= 20 and len(ports) >= 10:
            findings.append({'detection': 'suspicious-network', 'attempts': len(group), 'distinct_ports': len(ports), 'evidence': sorted(e['event_uid'] for e in group)})
    return sorted(findings, key=lambda f: (f['detection'], f['evidence']))


def read_events(directory):
    return [json.loads(line) for path in sorted(directory.glob('*.jsonl')) for line in path.read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', type=Path, default=ROOT/'logs')
    parser.add_argument('--output', type=Path, help='Optional JSON findings artifact')
    args = parser.parse_args()
    events = read_events(args.logs)
    if not events:
        parser.error('No JSONL events found')
    output = json.dumps({'validation': 'offline reference only', 'event_count': len(events), 'findings': detect(events)}, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(output, end='')


if __name__ == '__main__':
    main()
