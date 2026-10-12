"""Executable catalog publisher with explicit cooperative local permission checks.

The publisher's data operations use three named files. The runner prepares an
owned directory. These checks are a testable application model, not an OS
sandbox, IAM permission policy, credential verifier, or deployment authority.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from fse_workflow.conformance import effective_policy_accepts
from fse_workflow.fragment import inspect_policy
from fse_workflow.io import load_json, save_json

OPERATIONS = (("read", "input/catalog.json"),
              ("write", "dist/catalog.json"),
              ("write", "dist/index.html"))


def publish(root: Path, policy: dict, identity: dict) -> list[dict]:
    """Execute fixed operations; raise before the first unauthorized file access."""
    if not inspect_policy(policy["trust"])["supported"]:
        raise ValueError("unsupported trust policy")
    if not effective_policy_accepts(policy["trust"], identity):
        raise PermissionError("release identity not admitted")
    grants = policy["permissions"]
    if not isinstance(grants, list) or any(
        not isinstance(g, dict) or set(g) != {"sub", "aud", "action", "resource"}
        or any(not isinstance(v, str) or not v for v in g.values()) for g in grants
    ):
        raise ValueError("exact local permission records required")
    trace = []

    def authorized_path(action, resource):
        requested = {**identity, "action": action, "resource": resource}
        if requested not in grants:
            raise PermissionError(f"missing {action} {resource}")
        path = (root / resource).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("operation outside owned root")
        return path

    source = authorized_path(*OPERATIONS[0])
    products = load_json(source)
    trace.append({"action": "read", "resource": OPERATIONS[0][1]})
    if not isinstance(products, list) or not products:
        raise ValueError("nonempty catalog required")
    ids = set()
    for product in products:
        if not isinstance(product, dict) or set(product) != {"id", "name", "price_cents"}:
            raise ValueError("invalid product fields")
        if any(not isinstance(product[k], str) or not product[k] for k in ("id", "name")):
            raise ValueError("product id and name must be nonempty strings")
        if type(product["price_cents"]) is not int or product["price_cents"] < 0:
            raise ValueError("nonnegative integer price required")
        if product["id"] in ids:
            raise ValueError("duplicate product id")
        ids.add(product["id"])
    ordered = sorted(products, key=lambda p: p["id"])
    catalog = authorized_path(*OPERATIONS[1])
    save_json(catalog, {"products": ordered, "count": len(ordered)})
    trace.append({"action": "write", "resource": OPERATIONS[1][1]})
    page = authorized_path(*OPERATIONS[2])
    rows = "".join(f"<li>{html.escape(p['name'])}: {p['price_cents']} cents</li>" for p in ordered)
    page.write_text("<!doctype html><title>Catalog</title><ul>" + rows + "</ul>\n", encoding="utf-8")
    trace.append({"action": "write", "resource": OPERATIONS[2][1]})
    return trace


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("main", "release"))
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args(argv)
    identity = {"sub": f"repo:owned/catalog:ref:refs/heads/{args.branch}", "aud": "sts.amazonaws.com"}
    try:
        trace = publish(args.root, load_json(args.policy), identity)
        result, code = {"status": "completed", "trace": trace}, 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result, code = {"status": "blocked", "reason": str(exc)}, 1
    save_json(args.result, result)
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
