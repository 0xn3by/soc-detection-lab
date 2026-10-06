"""Check portfolio evidence consistency and user-facing reproducibility paths."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ('brute-force', 'suspicious-powershell', 'admin-account-creation', 'suspicious-network')
DIRECTORIES = ('01-brute-force', '02-suspicious-powershell', '03-admin-account-creation', '04-suspicious-network-activity')


class ArtifactTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self):
        for path in ROOT.rglob('*.md'):
            if any(part.startswith('.') for part in path.relative_to(ROOT).parts):
                continue
            for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)', path.read_text()):
                if link.startswith(('https://', 'http://', '#', 'mailto:')):
                    continue
                target = link.split('#', 1)[0]
                self.assertTrue((path.parent/target).exists(), f'{path.relative_to(ROOT)}: {link}')

    def test_documented_spl_matches_canonical_files(self):
        for scenario, directory in zip(SCENARIOS, DIRECTORIES):
            canonical = (ROOT/'detections'/f'{scenario}.spl').read_text().strip()
            guide = (ROOT/'scenarios'/directory/'README.md').read_text()
            blocks = re.findall(r'```spl\n(.*?)\n```', guide, re.S)
            self.assertIn(canonical, blocks, scenario)

    def test_worked_cases_have_twenty_sections(self):
        cases = sorted((ROOT/'investigations').glob('incident-*.md'))
        self.assertEqual(len(cases), 4)
        for path in cases:
            numbers = [int(n) for n in re.findall(r'^## (\d+)\.', path.read_text(), re.M)]
            self.assertEqual(numbers, list(range(1, 21)), path.name)

    def test_dashboard_xml(self):
        app = ROOT/'setup'/'splunk-app'/'default'/'data'/'ui'
        root = ET.parse(app/'views'/'soc_overview.xml').getroot()
        self.assertEqual(root.tag, 'dashboard')
        searches = root.findall('.//search')
        self.assertEqual(len(searches), 4)
        for search in searches:
            self.assertIn('index=soc_lab', search.findtext('query'))
            self.assertEqual(search.findtext('earliest'), '0')
        ET.parse(app/'nav'/'default.xml')

    def test_report_cli_all_scenarios_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in SCENARIOS:
                output = Path(directory)/f'{scenario}.md'
                command = [sys.executable, str(ROOT/'scripts'/'generate_report.py'),
                           '--scenario', scenario, '--incident-id', 'LAB-TEST', '--output', str(output)]
                result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = output.read_text()
                self.assertNotIn('{{', report)
                self.assertIn('analyst decision required', report.lower())
                self.assertIn(hashlib.sha256((ROOT/'logs'/f'{scenario}.jsonl').read_bytes()).hexdigest(), report)
                for event in map(json.loads, (ROOT/'logs'/f'{scenario}.jsonl').read_text().splitlines()):
                    self.assertIn(event['event_uid'], report)
                again = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(again.returncode, 0)
                self.assertEqual(output.read_text(), report)

    def test_generator_cli_is_reproducible_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(ROOT/'scripts'/'generate_events.py'),
                                     '--output-dir', directory], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in SCENARIOS:
                fixture = ROOT/'logs'/f'{scenario}.jsonl'
                self.assertEqual((Path(directory)/fixture.name).read_bytes(), fixture.read_bytes())


if __name__ == '__main__':
    unittest.main()
