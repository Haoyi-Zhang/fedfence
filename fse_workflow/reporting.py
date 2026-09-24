"""Stable developer-facing renderers for FedFence gate results.

Renderers do not change verdict semantics.  SARIF and GitHub workflow commands
are transport formats for the same pass/fail/unknown object returned by the gate.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _is_change(obj: dict[str, Any]) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("after"), dict)


def effective_result(obj: dict[str, Any]) -> dict[str, Any]:
    return obj["after"] if _is_change(obj) else obj


def render_summary(obj: dict[str, Any]) -> str:
    if _is_change(obj):
        prefix = (
            f"Change review: {obj['before']['verdict']} -> {obj['after']['verdict']}\n"
            f"Unchanged contract: {obj['contract_unchanged']}\n"
            f"Confirmed contract regression: {obj.get('confirmed_contract_regression', False)}\n"
            f"Regression kind: {obj.get('regression_kind') or 'none'}\n"
        )
        return prefix + render_summary(obj["after"])
    lines = [
        f"FedFence: {str(obj.get('verdict', 'unknown')).upper()}",
        obj.get("scope", "No positive result is available."),
    ]
    if obj.get("changed_fields"):
        lines.append("Changed inputs: " + ", ".join(obj["changed_fields"]))
    for finding in obj.get("findings", []):
        label = finding.get("kind", finding.get("code", "finding"))
        where = f" [statement {finding['statement']}]" if finding.get("statement") is not None else ""
        detail = finding.get("message", finding.get("detail", ""))
        lines.append(f"- {label}{where}: {detail}")
        if finding.get("witness"):
            lines.append("  Counterexample: " + finding["witness"])
    lines.append("Deployment approval and live-source authenticity are not established by this check.")
    return "\n".join(lines)


def _escape_workflow(text: str) -> str:
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_github(obj: dict[str, Any]) -> str:
    result = effective_result(obj)
    verdict = result.get("verdict", "unknown")
    commands: list[str] = []
    for finding in result.get("findings", []):
        code = finding.get("kind", finding.get("code", "finding"))
        detail = finding.get("message", finding.get("detail", ""))
        witness = finding.get("witness")
        message = f"{detail}" + (f" | {witness}" if witness else "")
        level = "error" if verdict == "fail" else "warning"
        commands.append(f"::{level} title=FedFence { _escape_workflow(code) }::{_escape_workflow(message)}")
    if not commands:
        title = "FedFence pass" if verdict == "pass" else "FedFence unknown"
        level = "notice" if verdict == "pass" else "warning"
        commands.append(f"::{level} title={title}::{_escape_workflow(result.get('scope', ''))}")
    commands.append(render_summary(obj))
    return "\n".join(commands)


def render_sarif(obj: dict[str, Any], artifact: str | Path | None = None) -> dict[str, Any]:
    result = effective_result(obj)
    verdict = result.get("verdict", "unknown")
    findings = result.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("kind", finding.get("code", "fedfence-finding")))
        detail = finding.get("message", finding.get("detail", rule_id))
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {"text": detail[:240] or rule_id},
            "help": {"text": "Review the supplied trust packet, concrete witness, and evidence dependency."},
            "properties": {"security-severity": "8.0" if verdict == "fail" else "4.0"},
        })
        message = detail + (f" Witness: {finding['witness']}" if finding.get("witness") else "")
        item: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error" if verdict == "fail" else "warning",
            "message": {"text": message},
            "properties": {
                "fedfenceVerdict": verdict,
                "blocking": bool(finding.get("blocking", verdict != "pass")),
            },
        }
        if artifact:
            item["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(artifact)},
                    "region": {"startLine": 1},
                }
            }]
        sarif_results.append(item)
    invocation = {
        "executionSuccessful": True,
        "exitCode": int(result.get("exit_code", 2)),
        "properties": {
            "fedfenceVerdict": verdict,
            "replayOk": bool(result.get("replay_ok", False)),
            "deploymentAuthorized": bool(result.get("deployment_authorized", False)),
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FedFence",
                "informationUri": "https://example.invalid/fedfence",
                "semanticVersion": "1.0.0-research",
                "rules": sorted(rules.values(), key=lambda x: x["id"]),
            }},
            "invocations": [invocation],
            "results": sarif_results,
            "properties": {
                "scope": result.get("scope"),
                "sourceAuthenticityVerified": bool(result.get("source_authenticity_verified", False)),
            },
        }],
    }


def render(obj: dict[str, Any], fmt: str, artifact: str | Path | None = None) -> str:
    if fmt == "json":
        return json.dumps(obj, indent=2, sort_keys=True)
    if fmt == "text":
        return render_summary(obj)
    if fmt == "github":
        return render_github(obj)
    if fmt == "sarif":
        return json.dumps(render_sarif(obj, artifact), indent=2, sort_keys=True)
    raise ValueError(f"unsupported format: {fmt}")
