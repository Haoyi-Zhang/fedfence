"""Study accounting: missing labels are UNKNOWN, never counted as correct."""
from __future__ import annotations
from collections import Counter


def summarize(rows):
    ids=[r['unit_id'] for r in rows]
    if len(ids)!=len(set(ids)):
        raise ValueError('duplicate unit_id; deduplicate sampling units before analysis')
    if any(r.get('source_kind') not in {'public-repository','documentation','generated'} for r in rows):
        raise ValueError('every row requires an explicit source_kind')
    by_type=Counter(r['source_kind'] for r in rows)
    public=[r for r in rows if r['source_kind']=='public-repository']
    extracted=[r for r in public if r.get('extraction')=='extracted']
    supported=[r for r in extracted if r.get('support')=='supported']
    labeled=[]
    for r in rows:
        oracle=r.get('oracle',{})
        label=oracle.get('label','unknown')
        if label not in {'safe','unsafe','unknown'}:
            raise ValueError('invalid oracle label')
        if label!='unknown':
            if oracle.get('provenance') not in {'owner-confirmed','independent-double-review','synthetic-specification'}:
                raise ValueError('labeled row requires oracle provenance')
            if not oracle.get('evidence_ref'):
                raise ValueError('labeled row requires evidence reference')
            labeled.append(r)
    # Synthetic labels NEVER enter external-accuracy denominators.
    external_labeled=[r for r in labeled if r['source_kind']=='public-repository' and r['oracle']['provenance'] in {'owner-confirmed','independent-double-review'}]
    classified=[r for r in external_labeled if r.get('fedfence') in {'pass','fail'}]
    correct=sum((r['fedfence']=='pass')==(r['oracle']['label']=='safe') for r in classified)
    return {'candidate_units':len(rows),'source_kind_counts':dict(by_type),
            'public_repository_candidates':len(public),'public_extracted':len(extracted),'public_supported':len(supported),
            'coverage_over_candidates':len(supported)/len(public) if public else None,
            'coverage_over_extracted':len(supported)/len(extracted) if extracted else None,
            'external_labeled':len(external_labeled),'external_classified':len(classified),
            'external_unknown':len(external_labeled)-len(classified),
            'external_correct':correct,'external_accuracy_on_classified':correct/len(classified) if classified else None,
            'warning':'coverage and accuracy are descriptive of the declared sample only; unknown is not false positive or correct'}
