"""Finite study adapter over one explicit issuer relation; not the strict gate.

Inputs are frozen local data. This adapter does not establish source authenticity,
contract approval, freshness, workflow reachability, or live provider behavior.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Iterable
from .conformance import _glob_matches, ConformanceBudgetExceeded
from .decision import resolve
from .io import digest

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
        return asdict(self)

def _token(obj: Any) -> Token:
    if isinstance(obj, (list, tuple)) and len(obj) == 2:
        values = tuple(obj)
    elif isinstance(obj, dict) and {"sub", "aud"}.issubset(obj):
        values = (obj["sub"], obj["aud"])
    else:
        raise ValueError("token must contain sub and aud")
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError("token coordinates must be nonempty strings; no coercion")
    return values

def _rule(obj: Any) -> tuple[str, str, str]:
    sub, aud = _token(obj)
    op = obj.get("operator", "StringLike") if isinstance(obj, dict) else "StringLike"
    if op not in {"StringEquals", "StringLike"}:
        raise ValueError("unsupported normalized rule operator")
    return sub, aud, op

def _covered(token: Token, rules: list[tuple[str, str, str]]) -> bool:
    return any((token == (sub, aud)) if op == "StringEquals" else
               (_glob_matches(sub, token[0]) and _glob_matches(aud, token[1]))
               for sub, aud, op in rules)

def _unknown(code: str, detail: str) -> StudyResult:
    return StudyResult("unknown", 2, [Finding(code, detail)], [], [], [], digest([]))

def _decide(*, explicit_issuer: Iterable[Any], allow: Iterable[Any],
           deny: Iterable[Any] = (), intent: Iterable[Any],
           required: Iterable[Any] = (), invalid: Iterable[str] = ()) -> StudyResult:
    """Two-sided conformance; invalidity dominates reportable latent failures.

    Iterable inputs are materialized exactly once, preventing consumption of a
    generator from changing the policy between subjects. Only * and ? are globs;
    bracket characters are literals, as in the regular policy fragment.
    """
    try:
        G = {_token(t) for t in explicit_issuer}
        R = {_token(t) for t in required}
        allows, denies, intents = ([ _rule(t) for t in seq ]
                                   for seq in (allow, deny, intent))
        invalids = list(invalid)
        if any(not isinstance(s, str) or not s for s in invalids):
            raise ValueError("invalid reasons must be nonempty strings")
    except (TypeError, ValueError, KeyError) as exc:
        return _unknown("malformed-normalized-input", str(exc))
    findings: list[Finding] = []
    for t in sorted(R - G):
        findings.append(Finding("required-token-outside-issuer-domain",
                                "required identity is outside the explicit issuer model", t))
    for t in sorted(R):
        if not _covered(t, intents):
            findings.append(Finding("required-token-outside-intent",
                                    "required identity contradicts the upper-bound intent", t))
    if findings:
        invalids.append("inconsistent-positive-obligation")
    admitted = sorted(t for t in G if _covered(t, allows) and not _covered(t, denies))
    over = sorted(t for t in admitted if not _covered(t, intents))
    # A missing identity is confirmed only when both model and intent admit it.
    missing = sorted(t for t in (R & G) if _covered(t, intents) and t not in admitted)
    latent = [Finding("admission-expansion", "issuer-mintable token admitted outside intent", t)
              for t in over]
    latent += [Finding("required-token-not-admitted", "required identity is not admitted", t)
               for t in missing]
    d = resolve(invalid=bool(invalids), overgrant=bool(over), missing_required=bool(missing))
    if invalids:
        findings = [Finding("inconsistent-specification", s) for s in dict.fromkeys(invalids)] + findings
    else:
        findings, latent = latent, []
    return StudyResult(d.status, d.exit_code, findings, latent, admitted, sorted(G), digest(sorted(G)))

def decide(*, explicit_issuer: Iterable[Any], allow: Iterable[Any],
           deny: Iterable[Any] = (), intent: Iterable[Any],
           required: Iterable[Any] = (), invalid: Iterable[str] = ()) -> StudyResult:
    """Conservative wrapper: bounded membership exhaustion remains unknown."""
    try:
        return _decide(explicit_issuer=explicit_issuer, allow=allow, deny=deny,
                       intent=intent, required=required, invalid=invalid)
    except ConformanceBudgetExceeded as exc:
        return _unknown(exc.code, str(exc))

def certificate(packet: dict[str, Any], result: StudyResult) -> dict[str, Any]:
    body = {"schema": "fedfence.normalized-study-certificate.v1", "packet": packet,
            "decision": result.to_json(), "issuer_domain": result.issuer_domain,
            "issuer_domain_digest": result.issuer_domain_digest}
    # Hashes detect record changes; they are not signatures or source authentication.
    return {**body, "certificate_digest": digest(body)}

def replay(cert: dict[str, Any]) -> StudyResult:
    try:
        fields = {"schema", "packet", "decision", "issuer_domain", "issuer_domain_digest", "certificate_digest"}
        if not isinstance(cert, dict) or set(cert) != fields or cert["schema"] != "fedfence.normalized-study-certificate.v1":
            raise ValueError("unexpected certificate schema or fields")
        if cert["certificate_digest"] != digest({k:v for k,v in cert.items() if k != "certificate_digest"}):
            raise ValueError("certificate content digest mismatch")
        packet = cert["packet"]
        if not isinstance(packet, dict) or not {"explicit_issuer", "allow", "intent"}.issubset(packet):
            raise ValueError("incomplete replay packet")
        if set(packet) - {"explicit_issuer", "allow", "deny", "intent", "required", "invalid"}:
            raise ValueError("unknown replay packet field")
        got = decide(**packet)
        if digest(got.issuer_domain) != digest(cert["issuer_domain"]) or got.issuer_domain_digest != cert["issuer_domain_digest"]:
            return _unknown("issuer-domain-replay-mismatch", "different explicit issuer relation")
        if digest(got.to_json()) != digest(cert["decision"]):
            return _unknown("decision-replay-mismatch", "recomputed result differs, including findings and admitted tuples")
        return got
    except (TypeError, ValueError, KeyError) as exc:
        return _unknown("invalid-certificate", str(exc))
