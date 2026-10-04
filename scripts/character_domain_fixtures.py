"""Self-contained benign string-review fixtures; no tokens, credentials or cloud calls."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'artifact'))
from fedfence.regular import DEFAULT_ALPHABET
from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX
from scripts.make_workflow_examples import packet, rehash

SUB = 'repo:acme/api:ref:refs/heads/main'
AUD = 'sts.amazonaws.com'
BRANCH = 'repo:acme/api:ref:refs/heads/'
NOW = '2026-09-23T01:00:00Z'


def exhausted_case(coordinate='aud', *, closed=False, extra_literal=''):
    base = packet()
    policy = copy.deepcopy(base['snapshots']['policy']['body'])
    st = policy['Statement'][0]
    spec = {'allowed_subjects': [SUB], 'allowed_audiences': [AUD]}
    if coordinate == 'aud':
        pool = sorted(set(DEFAULT_ALPHABET) | {'*', '?'} | set(extra_literal))
        spec['allowed_audiences'] = pool
        spec['issuer_audiences'] = ['?']
        values, pattern = pool, '?'
    elif coordinate == 'sub':
        pool = sorted(set(DEFAULT_ALPHABET) | set(extra_literal))
        values = [BRANCH + ch for ch in pool if ch not in ':*?']
        spec['allowed_subjects'] = values
        spec['issuer_subjects'] = [BRANCH + '?']
        pattern = BRANCH + '?'
    else:
        raise ValueError(coordinate)
    st['Condition']['StringEquals'].pop(PREFIX + coordinate)
    op = 'StringEquals' if closed else 'StringLike'
    st['Condition'].setdefault(op, {})[PREFIX + coordinate] = values if closed else pattern
    return {'name': 'benign-character-domain-' + coordinate, 'policy': policy, 'spec': spec}


def exhausted_packet(*, closed=False):
    """Exercise the existing strict contract without widening its name profile."""
    p = packet()
    names = sorted(ch for ch in DEFAULT_ALPHABET if ch.isascii() and
                   (ch.isalnum() or ch in '-_./'))
    p['contract']['intent']['audiences'] = names
    p['contract']['required_tokens'] = [{'sub': SUB, 'aud': 'a', 'reason': 'benign positive control'}]
    p['contract']['review']['approved_digest'] = contract_digest(p['contract'])
    st = p['snapshots']['policy']['body']['Statement'][0]
    st['Condition']['StringEquals'].pop(PREFIX + 'aud')
    if closed:
        st['Condition']['StringEquals'][PREFIX + 'aud'] = names
    else:
        st['Condition']['StringLike'] = {PREFIX + 'aud': '?'}
    denied = sorted((set(DEFAULT_ALPHABET) | {'*','?'}) - set(names))
    deny = copy.deepcopy(st)
    deny['Effect'] = 'Deny'
    deny['Condition'] = {'StringEquals': {PREFIX + 'sub': SUB, PREFIX + 'aud': denied}}
    p['snapshots']['policy']['body']['Statement'].append(deny)
    rehash(p, 'policy')
    return p
