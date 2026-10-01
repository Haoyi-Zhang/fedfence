"""Finite, model-relative backend for the public-change study.

This module is intentionally separate from the strict user-facing CLI.  It consumes
already-normalized packets and therefore does not attest snapshot freshness, contract
approval, workflow reachability, or live provider state.  All positive and negative
obligations are evaluated over the *same explicit issuer relation*.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from fnmatch import fnmatchcase
import hashlib, json
from typing import Any, Iterable
from .decision import resolve

Token = tuple[str, str]

@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    token: Token | None = None

@dataclass
class StudyResult:
    status: str
    exit_code: int
    findings: list[Finding]
    latent_findings: list[Finding]
    admitted: list[Token]
    issuer_domain: list[Token]
    issuer_domain_digest: str
    entry_point: str = "study-only-normalized-backend"

    def to_json(self) -> dict[str, Any]:
        d=asdict(self)
        return d

def _token(obj: Any) -> Token:
    if isinstance(obj,(list,tuple)) and len(obj)==2:
        return (str(obj[0]),str(obj[1]))
    if isinstance(obj,dict) and "sub" in obj and "aud" in obj:
        return (str(obj["sub"]),str(obj["aud"]))
    raise ValueError(f"token must contain sub and aud: {obj!r}")

def _tokens(values: Iterable[Any]) -> set[Token]:
    return {_token(v) for v in values}

def _matches(token:Token, rule:Any)->bool:
    if isinstance(rule,dict):
        sub=str(rule.get("sub","")); aud=str(rule.get("aud",""))
    elif isinstance(rule,(list,tuple)) and len(rule)==2:
        sub,aud=map(str,rule)
    else:
        raise ValueError(f"invalid rule: {rule!r}")
    return fnmatchcase(token[0],sub) and fnmatchcase(token[1],aud)

def _covered(token:Token,rules:Iterable[Any])->bool:
    return any(_matches(token,r) for r in rules)

def _digest(domain:set[Token])->str:
    raw=json.dumps(sorted(domain),separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()

def decide(*, explicit_issuer:Iterable[Any], allow:Iterable[Any], deny:Iterable[Any]=(),
           intent:Iterable[Any], required:Iterable[Any]=(), invalid:Iterable[str]=()) -> StudyResult:
    """Evaluate a normalized packet over one explicit finite issuer relation.

    Precedence is conservative: any inconsistent/invalid specification yields
    ``unknown`` (exit 2), while retaining latent overgrant/missing diagnostics.
    Without invalidity, overgrant or required-token loss yields ``fail`` (exit 1).
    """
    findings=[]; latent=[]
    try:
        G=_tokens(explicit_issuer); R=_tokens(required)
    except Exception as e:
        G=set(); R=set(); invalid=[*invalid,f"malformed-token:{e}"]
    invalid=list(dict.fromkeys(str(x) for x in invalid if str(x)))
    # Required identities are positive obligations and must be issuer-mintable.
    outside=sorted(R-G)
    for t in outside:
        findings.append(Finding("required-token-outside-issuer-domain",
                                "required identity is outside the explicit issuer model",t))
    if outside:
        invalid.append("inconsistent-positive-obligation")
    admitted=sorted(t for t in G if _covered(t,allow) and not _covered(t,deny))
    over=sorted(t for t in admitted if not _covered(t,intent))
    missing=sorted(t for t in R if t not in set(admitted))
    latent.extend(Finding("admission-expansion","issuer-mintable token is admitted outside intent",t) for t in over)
    latent.extend(Finding("required-token-not-admitted","required issuer-mintable token is not admitted",t) for t in missing)
    if invalid:
        findings=[Finding("inconsistent-specification",x) for x in dict.fromkeys(invalid)] + findings
        d=resolve(invalid=True,overgrant=bool(over),missing_required=bool(missing))
        return StudyResult(d.status,d.exit_code,findings,latent,admitted,sorted(G),_digest(G))
    if latent:
        d=resolve(invalid=False,overgrant=bool(over),missing_required=bool(missing))
        return StudyResult(d.status,d.exit_code,latent,[],admitted,sorted(G),_digest(G))
    d=resolve(invalid=False,overgrant=False,missing_required=False)
    return StudyResult(d.status,d.exit_code,[],[],admitted,sorted(G),_digest(G))

def certificate(packet:dict[str,Any], result:StudyResult)->dict[str,Any]:
    body={
        "schema":"fedfence.normalized-study-certificate.v1",
        "packet":packet,
        "decision":result.to_json(),
        "issuer_domain":result.issuer_domain,
        "issuer_domain_digest":result.issuer_domain_digest,
    }
    body["certificate_digest"]=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    return body

def replay(cert:dict[str,Any])->StudyResult:
    p=cert["packet"]
    got=decide(explicit_issuer=p.get("explicit_issuer",[]),allow=p.get("allow",[]),deny=p.get("deny",[]),
               intent=p.get("intent",[]),required=p.get("required",[]),invalid=p.get("invalid",[]))
    if got.issuer_domain_digest!=cert.get("issuer_domain_digest"):
        return StudyResult("unknown",2,[Finding("issuer-domain-replay-mismatch","certificate and replay use different issuer domains")],[],got.admitted,got.issuer_domain,got.issuer_domain_digest)
    recorded=cert.get("decision",{})
    if got.status!=recorded.get("status") or got.exit_code!=recorded.get("exit_code"):
        return StudyResult("unknown",2,[Finding("decision-replay-mismatch","recorded and replayed decisions differ")],[],got.admitted,got.issuer_domain,got.issuer_domain_digest)
    return got
