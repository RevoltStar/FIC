#!/usr/bin/env python3
"""Historical evidence stays independent of live sources and fails on tampering."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class HistoricalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.here = self.root / HERE.relative_to(ROOT)
        self.here.mkdir(parents=True)
        for name in ('check-evidence.py', 'evidence.json', 'contracts.py'):
            shutil.copyfile(HERE / name, self.here / name)
        shutil.copytree(HERE / 'reports', self.here / 'reports')
        self.evidence = json.loads((self.here / 'evidence.json').read_text())

    def check(self, success):
        result = subprocess.run(
            [sys.executable, str(self.here / 'check-evidence.py')],
            cwd=self.root, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode == 0, success,
                         result.stdout + result.stderr)
        if success:
            self.assertIn('Historical I6 five-platform matrix PASS', result.stdout)
            self.assertIn('does not certify current HEAD', result.stdout)
        return result

    def build_report(self):
        row = next(iter(self.evidence['profiles'].values()))
        return self.root / row['build']['path']

    def test_accepted_matrix(self):
        self.check(True)

    def test_unrelated_ssh_change(self):
        path = Path('fic/src/modules/net/ssh/Ssh.cpp')
        target = self.root / path
        target.parent.mkdir(parents=True)
        target.write_bytes((ROOT / path).read_bytes() + b'\n// unrelated SSH change\n')
        self.check(True)

    def test_live_contract_change(self):
        (self.here / 'contracts.py').write_text(
            "PLATFORMS=()\nSCENARIOS=()\nPOSITIVE=()\n"
            "raise RuntimeError('live contracts must not be imported')\n")
        self.check(True)

    def test_evidence_bytes_are_pinned(self):
        path = self.here / 'evidence.json'
        path.write_bytes(path.read_bytes() + b'\n')  # same JSON, different bytes
        result = self.check(False)
        self.assertIn('historical I6 evidence.json SHA-256 mismatch', result.stderr)

    def test_corrupted_report(self):
        path = self.build_report()
        content = bytearray(path.read_bytes())
        content[len(content) // 2] ^= 0xff
        path.write_bytes(content)
        self.check(False)

    def test_missing_scenario_report(self):
        row = next(iter(self.evidence['profiles'].values()))
        (self.root / row['scenarios']['positive']['path']).unlink()
        self.check(False)

    def test_recompressed_report_hash_is_checked(self):
        path = self.build_report()
        original = path.read_bytes()
        raw = gzip.decompress(original)
        replacement = gzip.compress(raw, mtime=1)
        self.assertNotEqual(original, replacement)
        self.assertEqual(gzip.decompress(replacement), raw)
        path.write_bytes(replacement)
        self.check(False)


if __name__ == '__main__':
    unittest.main()
