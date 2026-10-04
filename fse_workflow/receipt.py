"""Replayable two-sided review receipts for the existing strict FedFence gate.

This binds a full packet and semantic outcome, including required identities.
The receipt is not trusted as a cache: replay reruns the existing gate at the
caller's explicit check time and checks current implementation dependencies.
"""
from __future__ import annotations
from typing import Any
from .io import digest

FIELDS = ("verdict", "exit_code", "packet_sha256", "input_hashes", "fragment",
          "certificate_sha256", "required_token_checks", "findings", "replay_ok")

def semantic_view(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result.get(key) for key in FIELDS}

def make_receipt(packet: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    if result.get("packet_sha256") is not None and result["packet_sha256"] != digest(packet):
        raise ValueError("result does not describe the supplied packet")
    body = {"schema": "fedfence-two-sided-receipt-v1", "packet": packet,
            "decision": semantic_view(result), "source_authenticity_verified": False}
    return {**body, "receipt_sha256": digest(body)}

def replay_receipt(receipt: dict[str, Any], *, now=None, timeout: float = 15.0) -> dict[str, Any]:
    from .gate import review
    def unknown(code, detail):
        return {"verdict": "unknown", "exit_code": 2, "receipt_replay_ok": False,
                "findings": [{"code": code, "detail": detail}]}
    try:
        if not isinstance(receipt, dict) or set(receipt) != {"schema", "packet", "decision", "source_authenticity_verified", "receipt_sha256"}:
            raise ValueError("invalid receipt fields")
        if receipt["schema"] != "fedfence-two-sided-receipt-v1" or receipt["source_authenticity_verified"] is not False:
            raise ValueError("invalid receipt schema or authenticity assertion")
        if digest({k:v for k,v in receipt.items() if k != "receipt_sha256"}) != receipt["receipt_sha256"]:
            raise ValueError("receipt digest mismatch")
        got = review(receipt["packet"], now=now, timeout=timeout)
        if digest(semantic_view(got)) != digest(receipt["decision"]):
            result = unknown("receipt-replay-disagreement", "current gate result differs; the recorded result is not reusable")
            result["current_result"] = got
            return result
        return {**got, "receipt_replay_ok": True}
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        return unknown("invalid-receipt", str(exc))
