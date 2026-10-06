#!/usr/bin/env python3
"""Write deterministic, inert SOC fixtures. Never execute telemetry commands."""
import argparse
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ('brute-force', 'suspicious-powershell', 'admin-account-creation', 'suspicious-network')
BASE = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)


def generate(scenario):
    events = []
    def add(second, hostname, username, event_type, result, **fields):
        events.append(dict(timestamp=(BASE + timedelta(seconds=second)).isoformat().replace('+00:00', 'Z'),
                           event_uid=f'{scenario}-{len(events)+1:03d}', scenario=scenario,
                           synthetic=True, hostname=hostname, username=username,
                           event_type=event_type, result=result, **fields))
    if scenario == 'brute-force':
        for i in range(8):
            add(i*20, 'linux-web-01', 'alex', 'authentication', 'failure',
                src_ip='192.0.2.50', process='sshd', auth_method='password', log_source='linux_auth')
        add(170, 'linux-web-01', 'alex', 'authentication', 'success', src_ip='192.0.2.50',
            process='sshd', auth_method='password', log_source='linux_auth')
        for second, result in [(30, 'failure'), (50, 'failure'), (70, 'success')]:
            add(second, 'linux-web-01', 'sam', 'authentication', result, src_ip='192.0.2.20',
                process='sshd', auth_method='password', log_source='linux_auth')
    elif scenario == 'suspicious-powershell':
        encoded = base64.b64encode("Write-Output 'SOC LAB ONLY'".encode('utf-16le')).decode()
        add(600, 'win-workstation-01', 'LAB\\jordan', 'process_start', 'success', event_id=1,
            log_source='sysmon_normalized', process='powershell.exe', parent_process='winword.exe',
            process_guid='lab-ps-001', parent_guid='lab-word-001',
            command_line=f'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}')
        add(601, 'win-workstation-01', 'LAB\\jordan', 'script_block', 'observed', event_id=4104,
            log_source='powershell_normalized', process='powershell.exe', process_guid='lab-ps-001',
            script_text="Write-Output 'SOC LAB ONLY'")
        add(620, 'win-workstation-01', 'LAB\\itadmin', 'process_start', 'success', event_id=1,
            log_source='sysmon_normalized', process='powershell.exe', parent_process='explorer.exe',
            process_guid='lab-ps-002', parent_guid='lab-explorer-001', command_line='powershell.exe -File C:\\IT\\inventory.ps1')
    elif scenario == 'admin-account-creation':
        add(1200, 'win-server-01', 'LAB\\helpdesk', 'process_start', 'success', event_id=1,
            log_source='sysmon_normalized', process='net.exe', parent_process='cmd.exe',
            process_guid='lab-net-001', command_line='net user lab_backup /add', target_user='lab_backup')
        add(1202, 'win-server-01', 'LAB\\helpdesk', 'account_created', 'success', event_id=4720,
            log_source='windows_security_normalized', actor='LAB\\helpdesk', target_user='lab_backup', logon_id='0xLAB42')
        add(1210, 'win-server-01', 'LAB\\helpdesk', 'group_member_added', 'success', event_id=4732,
            log_source='windows_security_normalized', actor='LAB\\helpdesk', target_user='lab_backup',
            group_name='Administrators', group_sid='S-1-5-32-544', logon_id='0xLAB42')
        add(1230, 'win-server-01', 'LAB\\itadmin', 'group_member_added', 'success', event_id=4732,
            log_source='windows_security_normalized', actor='LAB\\itadmin', target_user='lab_reader',
            group_name='Users', group_sid='S-1-5-32-545', logon_id='0xLAB43')
    elif scenario == 'suspicious-network':
        for i in range(24):
            add(1800+i*2, 'linux-client-01', 'casey', 'network_connection', 'blocked',
                log_source='firewall_normalized', src_ip='192.0.2.60', dest_ip='198.51.100.20',
                dest_port=8000+i, protocol='tcp', process='python3', process_guid='lab-scan-001')
        for i in range(4):
            add(1800+i*10, 'linux-client-01', 'casey', 'network_connection', 'allowed',
                log_source='firewall_normalized', src_ip='192.0.2.60', dest_ip='203.0.113.10',
                dest_port=443, protocol='tcp', process='browser', process_guid='lab-browser-001')
    else:
        raise ValueError(scenario)
    return sorted(events, key=lambda e: (e['timestamp'], e['event_uid']))


def main(default=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=(*SCENARIOS, 'all'), default=default or 'all')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'logs')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS if args.scenario == 'all' else (args.scenario,):
        path = args.output_dir / f'{scenario}.jsonl'
        data = ''.join(json.dumps(e, sort_keys=True) + '\n' for e in generate(scenario))
        if not path.exists() or path.read_text() != data:
            path.write_text(data)
        print(f'{path}: {len(generate(scenario))} events')


if __name__ == '__main__':
    main()
