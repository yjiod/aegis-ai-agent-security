import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PolicyEnvelopeSignerTests(unittest.TestCase):
    def test_real_signer_and_public_interoperability_vectors(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'vectors.json'
            subprocess.run(['node', '--experimental-strip-types', '--no-warnings',
                            'scripts/test-policy-envelope.mjs', str(path)],
                           cwd=ROOT, check=True, capture_output=True, text=True)
            cases = json.loads(path.read_text())
            self.assertGreaterEqual(len(cases), 50)
            self.assertEqual(len({case['name'] for case in cases}), len(cases))
            self.assertEqual(cases[0]['expected'], 'accepted')
