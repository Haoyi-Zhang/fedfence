"""Change-aware local review gate. Never treats a previous receipt as a proof.

A PASS concerns the supplied snapshots under declared semantics. It is not a live
cloud assurance, reviewer-authentication result, or end-to-end exploit judgment.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import math
import os
import subprocess
import sys
import time
from .contract import InvalidPacket, check_snapshots, compile_contract, compile_required_tokens
from .fragment import inspect_policy
from .conformance import check_required_tokens
from .io import canonical_bytes, digest
from .decision import resolve

ROOT = Path(__file__).resolve().parents[1]


def implementation_digest():
    h = hashlib.sha256()
    for folder in (ROOT / "artifact" / "fedfence", ROOT / "fse_workflow"):
        for p in sorted(folder.glob("*.py")):
            h.update(str(p.relative_to(ROOT)).encode()); h.update(b"\0"); h.update(p.read_bytes())
    return h.hexdigest()


def review(packet, *, now=None, previous=None, timeout=15.0):
    now = datetime.now(timezone.utc) if now is None else now
    started = time.monotonic()
    result = {"schema": "fedfence-gate-result-v1", "verdict": "unknown", "exit_code": 2,
              "scope": "relative to supplied snapshots and reviewed specification; not live-cloud safety",
              "source_authenticity_verified": False, "reviewer_identity_verified": False,
              "cache_used_for_verdict": False, "workflow_reachability_checked": False,
              "runtime_provider_behavior_verified": False, "deployment_authorized": False, "findings": [], "changed_fields": [], "replay_ok": False}
    try:
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0 or timeout > sys.float_info.max or not math.isfinite(timeout):
            raise InvalidPacket("invalid-timeout", "analysis timeout must be finite and positive")
        if not isinstance(packet, dict) or packet.get("schema") != "fedfence-review-packet-v1":
            raise InvalidPacket("invalid-packet", "expected fedfence-review-packet-v1")
        if set(packet) != {"schema", "contract", "snapshots"}:
            raise InvalidPacket("invalid-packet", "unknown/missing top-level fields")
        deadline = started + timeout
        contract = packet["contract"]
        spec = compile_contract(contract)
        required_tokens = compile_required_tokens(contract, spec)
        snaps, governance = check_snapshots(packet, contract, now)
        current_hashes = {"contract": digest(contract), "implementation": implementation_digest()}
        current_hashes.update({name: digest(snap) for name, snap in snaps.items()})
        result["input_hashes"] = current_hashes
        result["packet_sha256"] = digest(packet)
        prior_hashes = previous.get("input_hashes", {}) if isinstance(previous, dict) else {}
        if not isinstance(prior_hashes, dict):
            prior_hashes = {}
        result["changed_fields"] = [k for k in current_hashes if current_hashes[k] != prior_hashes.get(k)]
        policy = snaps["policy"]["body"]
        support = inspect_policy(policy)
        result["fragment"] = support
        if not support["supported"]:
            result["findings"] = support["issues"]
            return result
        # Exact profile validation precedes the retained corrected engine.
        case = {"name": contract["target_role"], "policy": policy, "spec": spec,
                "repository_governance": governance}
        worker = ROOT / "fse_workflow" / "backend.py"
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InvalidPacket("analysis-timeout", "review budget exhausted before backend invocation")
        proc = subprocess.run([sys.executable, str(worker)], input=canonical_bytes(case),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining, env=env)
        if proc.returncode:
            raise InvalidPacket("backend-error", proc.stderr.decode(errors="replace")[-1200:])
        obj = json.loads(proc.stdout)
        result["backend_analysis"] = obj["analysis"]
        result["replay_ok"] = obj["replay_ok"] is True
        result["certificate_sha256"] = digest(obj["certificate"])
        result["certificate"] = obj["certificate"]
        result["findings"] = obj["analysis"]["findings"]
        cert_safe = obj["certificate"].get("verdict") == "safe"
        # The certificate's verdict must agree; a failed replay cannot certify either answer.
        if not result["replay_ok"] or cert_safe != obj["analysis"]["safe"]:
            raise InvalidPacket("replay-disagreement", "analysis and certificate replay disagree")

        conformance = check_required_tokens(policy, spec, required_tokens, deadline=deadline)
        result["required_token_checks"] = conformance
        for item in conformance["missing"]:
            result["findings"].append({
                "code": "required-token-not-admitted",
                "kind": "required-token-not-admitted",
                "detail": item["reason"],
                "witness": f"sub={item['sub']}; aud={item['aud']}",
                "blocking": True,
            })
        for item in conformance["invalid"]:
            result["findings"].append({
                "code": "required-token-outside-contract-model",
                "kind": "required-token-outside-contract-model",
                "detail": item["reason"],
                "witness": f"sub={item['sub']}; aud={item['aud']}",
                "blocking": True,
            })

        has_overgrant = any(
            f.get("kind") in {"subject-overgrant", "audience-overgrant"} and f.get("witness")
            for f in result["findings"]
        )
        decision = resolve(invalid=bool(conformance["invalid"]),
                           overgrant=bool(has_overgrant),
                           missing_required=bool(conformance["missing"]))
        if conformance["invalid"] or has_overgrant or conformance["missing"] or obj["analysis"]["safe"]:
            result.update(verdict=decision.status, exit_code=decision.exit_code)
        # Diagnostics or missing evidence alone are UNKNOWN, not confirmed vulnerability.
        return result
    except subprocess.TimeoutExpired:
        result["findings"].append({"code": "analysis-timeout", "detail": "analysis budget exhausted; no positive result"})
    except (InvalidPacket, ValueError, TypeError, KeyError, OSError, OverflowError, RecursionError) as exc:
        result["findings"].append({"code": getattr(exc, "code", "invalid-packet"), "detail": str(exc)})
    result.update(verdict="unknown", exit_code=2)
    return result


def compare(before, after, *, now=None, timeout=15.0):
    left = review(before, now=now, timeout=timeout)
    right = review(after, now=now, previous=left, timeout=timeout)
    unchanged = before.get("contract") == after.get("contract") if isinstance(before, dict) and isinstance(after, dict) else False
    confirmed = unchanged and left["verdict"] == "pass" and right["verdict"] == "fail"
    kinds = {finding.get("kind", finding.get("code")) for finding in right.get("findings", [])}
    admission_expansion = confirmed and bool(kinds & {"subject-overgrant", "audience-overgrant"})
    required_identity_loss = confirmed and "required-token-not-admitted" in kinds
    regression_kind = "admission-expansion" if admission_expansion else "required-identity-loss" if required_identity_loss else None
    return {"schema": "fedfence-change-review-v2", "before": left, "after": right,
            "contract_unchanged": unchanged,
            "confirmed_contract_regression": confirmed,
            "confirmed_admission_regression": admission_expansion,
            "confirmed_required_identity_regression": required_identity_loss,
            "regression_kind": regression_kind,
            "intent_change_requires_review": not unchanged,
            "meaning": "a confirmed regression requires an unchanged reviewed contract, pass-to-fail replay, and a concrete overgrant or missing required identity"}
