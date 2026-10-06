import base64
import copy
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gen, analyzer = module('generate_events'), module('analyze_events')


class LabTests(unittest.TestCase):
    def test_fixtures_reproducible_schema_unique(self):
        ids = []
        for scenario in gen.SCENARIOS:
            events = gen.generate(scenario)
            fixture = [json.loads(line) for line in (ROOT/'logs'/f'{scenario}.jsonl').read_text().splitlines()]
            self.assertEqual(events, fixture)
            for e in events:
                self.assertTrue(e['synthetic'])
                self.assertTrue({'timestamp','hostname','username','event_type','result','event_uid','log_source'} <= e.keys())
                datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00'))
                ids.append(e['event_uid'])
        self.assertEqual(len(ids), len(set(ids)))

    def test_exact_expected_findings_and_duplicate_ingestion(self):
        events = sum([gen.generate(s) for s in gen.SCENARIOS], [])
        findings = analyzer.detect(events)
        self.assertEqual(len(findings), 4)
        self.assertEqual(findings, analyzer.detect(events*2))
        by_name = {f['detection']: f for f in findings}
        self.assertEqual(by_name['brute-force']['failed_attempts'], 8)
        self.assertEqual(by_name['suspicious-network']['distinct_ports'], 24)
        self.assertEqual(by_name['suspicious-powershell']['evidence'], ['suspicious-powershell-001'])
        self.assertEqual(by_name['admin-account-creation']['evidence'], ['admin-account-creation-003'])

    def test_auth_threshold_and_grouping(self):
        events = [e for e in gen.generate('brute-force') if e['username']=='alex' and e['result']=='failure']
        self.assertEqual(analyzer.detect(events[:4]), [])
        self.assertEqual(len(analyzer.detect(events[:5])), 1)
        split = copy.deepcopy(events[:5])
        split[-1]['src_ip'] = '192.0.2.99'
        self.assertEqual(analyzer.detect(split), [])
        split[-1]['src_ip'] = '192.0.2.50'
        split[-1]['timestamp'] = '2026-01-15T10:05:00Z'
        self.assertEqual(analyzer.detect(split), [])

    def test_network_thresholds_and_window(self):
        events = [e for e in gen.generate('suspicious-network') if e['result']=='blocked']
        self.assertEqual(analyzer.detect(events[:19]), [])
        self.assertEqual(len(analyzer.detect(events[:20])), 1)
        few_ports = copy.deepcopy(events)
        for i, e in enumerate(few_ports):
            e['dest_port'] = 8000+i%9
        self.assertEqual(analyzer.detect(few_ports), [])
        for i, e in enumerate(few_ports):
            e['dest_port'] = 8000+i%10
        self.assertEqual(len(analyzer.detect(few_ports)), 1)
        for i, e in enumerate(events):
            e['timestamp'] = (gen.BASE+timedelta(seconds=i*60)).isoformat()
        self.assertEqual(analyzer.detect(events), [])

    def test_powershell_safe_payload_and_negative_control(self):
        events = gen.generate('suspicious-powershell')
        command = events[0]['command_line']
        self.assertEqual(base64.b64decode(command.split()[-1]).decode('utf-16le'), "Write-Output 'SOC LAB ONLY'")
        self.assertEqual(analyzer.detect(events[1:]), [])
        e = copy.deepcopy(events[0])
        e['command_line'] = 'pwsh.exe -ENC abc'
        e['process'] = 'PWSH.EXE'
        self.assertEqual(len(analyzer.detect([e])), 1)
        e['command_line'] = 'pwsh.exe -Encoding utf8'
        self.assertEqual(analyzer.detect([e]), [])

    def test_admin_requires_successful_privileged_change(self):
        events = gen.generate('admin-account-creation')
        self.assertEqual(analyzer.detect(events[:2]+events[3:]), [])
        e = copy.deepcopy(events[2])
        e['result'] = 'failure'
        self.assertEqual(analyzer.detect([e]), [])

    def test_detection_field_contracts(self):
        # Explicit contracts tie every source field used by SPL to applicable fixtures.
        contracts = {
            'brute-force': ('authentication', 'event_uid hostname username src_ip result'),
            'suspicious-powershell': ('process_start', 'event_uid hostname username process parent_process process_guid command_line'),
            'admin-account-creation': ('group_member_added', 'event_uid hostname actor target_user group_name group_sid logon_id result'),
            'suspicious-network': ('network_connection', 'event_uid hostname username src_ip dest_ip protocol dest_port result'),
        }
        for scenario, (kind, fields) in contracts.items():
            spl = (ROOT/'detections'/f'{scenario}.spl').read_text()
            self.assertIn('index=soc_lab', spl)
            for e in gen.generate(scenario):
                if e['event_type'] == kind:
                    self.assertTrue(set(fields.split()) <= e.keys())
            for field in fields.split():
                self.assertIn(field, spl)


if __name__ == '__main__':
    unittest.main()
