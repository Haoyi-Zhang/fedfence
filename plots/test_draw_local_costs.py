"""Standard-library validation/whisker tests; no full generate or experiments."""
import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import draw_local_costs as plot


class ScalingTests(unittest.TestCase):
    def setUp(self):
        self.folder=plot.ARTIFACT/'tosem/results'
        self.record=json.loads((self.folder/'local_scaling.json').read_text(encoding='utf-8'))
        with (self.folder/'local_scaling.csv').open(newline='',encoding='utf-8') as stream:
            self.rows=list(csv.DictReader(stream))

    def test_standard_library_import(self):
        self.assertIsNone(plot.pdfmetrics)
        self.assertIsNone(plot.canvas)

    def test_all_54_runs_18_cells_and_three_six_point_series(self):
        plot.validate_scaling(self.rows,self.record)
        tables=plot.load_scaling(self.folder)
        self.assertEqual([len(rows) for rows in tables.values()],[6,6,6])
        for rows in tables.values():
            self.assertEqual([int(r['n']) for r in rows],plot.SIZES)
        self.assertEqual(sum(len(rows) for rows in tables.values()),18)

    def test_missing_duplicate_unknown_size_task_repetition_rejected(self):
        variants=[self.rows[:-1]]
        rows=copy.deepcopy(self.rows);rows[-1]=rows[0];variants.append(rows)
        for key,value in (('required_tokens','3'),('task','warmup'),('repetition','3'),('repetition','True')):
            rows=copy.deepcopy(self.rows);rows[0][key]=value;variants.append(rows)
        for rows in variants:
            with self.assertRaises(ValueError):plot.validate_scaling(rows,self.record)

    def test_bad_times_and_both_wrong_verdicts_rejected(self):
        for value in ('nan','inf','-1','0','bad'):
            rows=copy.deepcopy(self.rows);rows[0]['seconds']=value
            with self.assertRaises(ValueError):plot.validate_scaling(rows,self.record)
        rows=copy.deepcopy(self.rows);rows[0]['expected']=rows[0]['verdict']='fail'
        with self.assertRaises(ValueError):plot.validate_scaling(rows,self.record)

    def test_denominators_and_boolean_sizes_rejected(self):
        for key,value in (('recorded_runs',53),('repetitions',2),('warmup_runs',True),('sizes',[True,2,4,8,16,32])):
            record=copy.deepcopy(self.record);record[key]=value
            with self.assertRaises(ValueError):plot.validate_scaling(self.rows,record)

    def test_summary_stat_errors_duplicate_order_and_missing_cells_rejected(self):
        for field,value in (('median_seconds',.2),('min_seconds',-1),('max_seconds',float('inf')),
                            ('repetitions',True),('required_tokens',True)):
            record=copy.deepcopy(self.record);record['summary'][0][field]=value
            with self.assertRaises(ValueError):plot.validate_scaling(self.rows,record)
        for edit in ('missing','duplicate','order'):
            record=copy.deepcopy(self.record)
            if edit=='missing':record['summary'].pop()
            if edit=='duplicate':record['summary'][-1]=record['summary'][0]
            if edit=='order':record['summary'][0],record['summary'][3]=record['summary'][3],record['summary'][0]
            with self.assertRaises(ValueError):plot.validate_scaling(self.rows,record)

    def test_binding_duplicate_json_nonfinite_and_header_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            csv_text=(self.folder/'local_scaling.csv').read_text(encoding='utf-8')
            (folder/'local_scaling.csv').write_text(csv_text,encoding='utf-8')
            for text in ('{"passed":true,"passed":false}', '{"passed":NaN}'):
                (folder/'local_scaling.json').write_text(text,encoding='utf-8')
                with self.assertRaises(ValueError):plot.load_scaling(folder)
            record=copy.deepcopy(self.record);record['csv_sha256']='0'*64
            (folder/'local_scaling.json').write_text(json.dumps(record),encoding='utf-8')
            with self.assertRaises(ValueError):plot.load_scaling(folder)
            (folder/'local_scaling.csv').write_text('task,task\nx,x\n',encoding='utf-8')
            (folder/'local_scaling.json').write_text(json.dumps(self.record),encoding='utf-8')
            with self.assertRaises(ValueError):plot.load_scaling(folder)

    def test_all_medians_minmax_whiskers_and_shapes_preserved(self):
        tables=plot.load_scaling(self.folder)
        canvas=Mock()
        with patch.object(plot,'new_pdf',return_value=canvas), \
             patch.object(plot,'axes',side_effect=lambda *a,**kw:lambda x,y:(float(x),float(y))), \
             patch.object(plot,'text'),patch.object(plot,'line_points') as points:
            plot.draw(430.00462*plot.PT,tables,Path('unused'))
        self.assertEqual([c.args[2] for c in points.call_args_list],['circle','square','triangle'])
        self.assertEqual([len(c.args[1]) for c in points.call_args_list],[6,6,6])
        self.assertEqual(canvas.line.call_count,18*3)
        expected=[]
        from decimal import Decimal
        for name in ('scaling-pass.dat','scaling-loss.dat','scaling-replay.dat'):
            for row in tables[name]:
                x=float(row['n']);median=Decimal(row['median'])
                lo=float(median-Decimal(row['lower']));hi=float(median+Decimal(row['upper']))
                expected.extend([(x,lo,x,hi),(x-2,lo,x+2,lo),(x-2,hi,x+2,hi)])
        self.assertEqual([c.args for c in canvas.line.call_args_list],expected)

    def test_protected_output_rejected(self):
        with self.assertRaises(ValueError):plot.prepare_output_dir(plot.ARTIFACT/'plots')


if __name__=='__main__':
    unittest.main(verbosity=2)
