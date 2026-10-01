"""Shared final decision precedence for the strict gate and normalized study."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class Decision:
    status:str
    exit_code:int

def resolve(*, invalid:bool, overgrant:bool, missing_required:bool)->Decision:
    # Invalid/inconsistent input prevents a supported semantic judgment.  Latent
    # conformance findings remain reportable, but cannot downgrade unknown to fail.
    if invalid:return Decision('unknown',2)
    if overgrant or missing_required:return Decision('fail',1)
    return Decision('pass',0)
