import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fse_workflow.gate import review
from fse_workflow.io import load_json
from fse_workflow.reporting import render_sarif, render_github

NOW='2026-09-23T01:00:00Z'

class ReportingTests(unittest.TestCase):
    def test_sarif_fail_contains_witness_rule(self):
        packet=load_json(ROOT/'examples/release_gate/after_wildcard.json')
        result=review(packet,now=NOW)
        sarif=render_sarif(result,'packet.json')
        self.assertEqual('2.1.0',sarif['version'])
        self.assertTrue(sarif['runs'][0]['results'])
        self.assertEqual('error',sarif['runs'][0]['results'][0]['level'])
        self.assertIn('pull_request',json.dumps(sarif))
    def test_github_unknown_is_warning(self):
        result=review(load_json(ROOT/'examples/release_gate/after_stale.json'),now=NOW)
        out=render_github(result)
        self.assertIn('::warning',out)
        self.assertIn('stale-snapshot',out)
    def test_cli_sarif_and_result_json(self):
        with tempfile.TemporaryDirectory() as d:
            sarif=Path(d)/'result.sarif'; raw=Path(d)/'raw.json'
            p=subprocess.run([sys.executable,'-m','fse_workflow.cli','review',str(ROOT/'examples/release_gate/after_wildcard.json'),'--now',NOW,'--format','sarif','--output',str(sarif),'--result-json',str(raw)],cwd=ROOT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=30)
            self.assertEqual(1,p.returncode,p.stderr)
            self.assertEqual('2.1.0',json.loads(sarif.read_text())['version'])
            self.assertEqual('fail',json.loads(raw.read_text())['verdict'])
    def test_action_and_schema_are_packaged(self):
        action=(ROOT/'action.yml').read_text()
        schema=json.loads((ROOT/'schemas/review-packet.schema.json').read_text())
        self.assertIn('using: composite',action)
        self.assertIn('result-json',action)
        self.assertEqual('FedFence review packet',schema['title'])

class ExtendedStudyTests(unittest.TestCase):
    def run_script(self,name):
        return subprocess.run([sys.executable,str(ROOT/'scripts'/name)],cwd=ROOT,capture_output=True,text=True,timeout=30)
    def test_source_frontier_frozen_denominator(self):
        p=self.run_script('run_source_frontier_study.py');self.assertEqual(0,p.returncode,p.stderr)
        data=json.loads((ROOT/'fse/results/source_frontier_summary.json').read_text())
        self.assertEqual(24,data['sample_size'])
        self.assertEqual(24,data['unique_repositories'])
        self.assertEqual(7,data['literal_or_constant_foldable'])
        self.assertEqual(17,data['requires_instantiation_or_host_evaluation'])
        self.assertGreaterEqual(data['missing_audience_condition_records'],5)
    def test_runtime_corpus_frozen_denominator(self):
        p=self.run_script('run_runtime_compatibility_study.py');self.assertEqual(0,p.returncode,p.stderr)
        data=json.loads((ROOT/'fse/results/runtime_compatibility_summary.json').read_text())
        self.assertEqual(12,data['records'])
        self.assertEqual(2,data['public_actions_success_runs'])
        self.assertEqual(11,data['runtime_breakage_or_denial_reports'])

if __name__=='__main__': unittest.main()
