import importlib.util, json, os, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).parents[1]; DOWNLOADS=ROOT/'public'/'downloads'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,DOWNLOADS/file); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class SentinelTests(unittest.TestCase):
    def setUp(self): self.agent=load('agent','sentinel_agent.py'); self.collector=load('collector','sentinel_collector.py'); self.policy=json.loads((DOWNLOADS/'sentinel-policy.json').read_text())
    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as d:
            report=self.agent.build_report(Path(d),self.policy)
            self.assertEqual(report['schema'],'sentinel.report/v1'); self.assertEqual(report['summary']['critical'],0)
    def test_secret_detection_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'app.py'; p.write_text('token="sk-abcdefghijklmnopqrstuvwxyz123456"')
            report=self.agent.build_report(Path(d),self.policy); f=next(x for x in report['findings'] if x['kind']=='hardcoded_secret')
            self.assertEqual(f['severity'],'critical'); self.assertTrue(f['evidence'].endswith('…')); self.assertNotIn('abcdefghijklmnopqrstuvwxyz',f['evidence'])
    def test_baseline_is_additive_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'AGENTS.md').write_text('# Existing\nkeep me')
            self.agent.install_baseline(root); self.agent.install_baseline(root)
            text=(root/'AGENTS.md').read_text(); self.assertIn('keep me',text); self.assertEqual(text.count(self.agent.MANAGED_MARKER),1); self.assertTrue((root/'.cursor/rules/sentinel-security.mdc').exists())
    def test_collector_contract(self):
        report={'schema':'sentinel.report/v1','device_id':'device-123','summary':{},'findings':[]}
        self.assertTrue(self.collector.valid_report(report)); self.assertFalse(self.collector.valid_report({'schema':'other'}))

if __name__=='__main__': unittest.main()
