from __future__ import annotations
import argparse
import json
from pathlib import Path
from .gate import compare, review
from .io import load_json, save_json
from .reporting import render
from .receipt import make_receipt, replay_receipt

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_UNKNOWN = 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review supplied CI/CD trust snapshots against a separate contract")
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("review", help="review one complete packet")
    one.add_argument("packet", type=Path)
    one.add_argument("--receipt-json", type=Path, help="seal a full two-sided review receipt; no signature or cache")
    one.add_argument("--previous", type=Path, help="previous result; used only to report changed dependencies")
    two = sub.add_parser("compare", help="compare complete before/after packets")
    two.add_argument("before", type=Path)
    two.add_argument("after", type=Path)
    three = sub.add_parser("replay", help="rerun a two-sided receipt against current code and freshness")
    three.add_argument("receipt", type=Path)
    for command in (one, two, three):
        command.add_argument("--now", help="ISO time for deterministic tests; omit in actual review")
        command.add_argument("--timeout", type=float, default=15.0)
        command.add_argument("--output", type=Path, help="write the selected presentation format")
        command.add_argument("--result-json", type=Path, help="always write the raw gate object as JSON")
        command.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text")
    args = parser.parse_args(argv)
    artifact = args.packet if args.command == "review" else args.after if args.command == "compare" else args.receipt
    try:
        if args.command == "review":
            packet = load_json(args.packet)
            obj = review(
                packet,
                now=args.now,
                previous=load_json(args.previous) if args.previous else None,
                timeout=args.timeout,
            )
            code = int(obj["exit_code"])
            if args.receipt_json:
                save_json(args.receipt_json, make_receipt(packet, obj))
        elif args.command == "replay":
            obj = replay_receipt(load_json(args.receipt), now=args.now, timeout=args.timeout)
            code = int(obj["exit_code"])
        else:
            obj = compare(load_json(args.before), load_json(args.after), now=args.now, timeout=args.timeout)
            code = int(obj["after"]["exit_code"])
    except (OSError, ValueError, OverflowError, RecursionError) as exc:
        obj = {
            "schema": "fedfence-gate-result-v1",
            "verdict": "unknown",
            "exit_code": EXIT_UNKNOWN,
            "scope": "input could not be parsed; no positive result is available",
            "deployment_authorized": False,
            "findings": [{"code": "input-error", "detail": str(exc), "blocking": True}],
        }
        code = EXIT_UNKNOWN
    text = render(obj, args.format, artifact=artifact)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    if args.result_json:
        save_json(args.result_json, obj)
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
