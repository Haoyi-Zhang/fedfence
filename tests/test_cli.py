import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class CLITests(unittest.TestCase):
    def run_cli(self,path,*extra):
        return subprocess.run([sys.executable,'-m','fse_workflow.cli','review',str(path),'--now','2026-09-23T01:00:00Z',*extra],cwd=ROOT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=30)
    def test_pass_exit_and_human_output(self):
        r=self.run_cli(ROOT/'examples/release_gate/before.json')
        self.assertEqual(0,r.returncode,r.stderr);self.assertIn('PASS',r.stdout)
        self.assertNotIn('replay_summary',r.stdout)
    def test_fail_exit_prints_witness(self):
        r=self.run_cli(ROOT/'examples/release_gate/after_wildcard.json')
        self.assertEqual(1,r.returncode,r.stderr);self.assertIn('pull_request',r.stdout)
    def test_unknown_exit(self):
        r=self.run_cli(ROOT/'examples/release_gate/after_stale.json')
        self.assertEqual(2,r.returncode,r.stderr);self.assertIn('stale-snapshot',r.stdout)
    def test_json_file_and_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'result.json'
            r=self.run_cli(ROOT/'examples/release_gate/before.json','--format','json','--output',str(p))
            self.assertEqual(json.loads(r.stdout),json.loads(p.read_text()))
            self.assertFalse(json.loads(r.stdout)['deployment_authorized'])
