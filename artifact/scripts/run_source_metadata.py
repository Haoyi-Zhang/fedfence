#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, sys
from pathlib import Path
from urllib.parse import urlparse
ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["group", "file", "name", "has_public_source", "has_source_url", "url_host", "expected_safe", "normalized_sha256"]

def main() -> int:
    rows=[]; ok=True
    for group, dirname in [("registered-public", "public_examples"), ("optional-public-issue", "external_evidence"), ("provider-drift", "provider_drift_cases")]:
        for path in sorted((ROOT / dirname).glob("*.json")):
            obj=json.loads(path.read_text())
            url=str(obj.get("source_url", ""))
            host=urlparse(url).netloc
            canonical=json.dumps(obj, sort_keys=True, separators=(",", ":"))
            digest=hashlib.sha256(canonical.encode()).hexdigest()
            row={
                "group": group,
                "file": path.name,
                "name": obj.get("name", ""),
                "has_public_source": bool(obj.get("public_source")),
                "has_source_url": bool(url.startswith("https://") and host),
                "url_host": host,
                "expected_safe": obj.get("expected_safe"),
                "normalized_sha256": digest,
            }
            rows.append(row)
            ok = ok and row["has_public_source"] and row["has_source_url"] and isinstance(row["expected_safe"], bool) and len(digest)==64
    out=ROOT/"results"; out.mkdir(exist_ok=True)
    with (out/"public_source_metadata.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    manifest={"examples": len(rows), "registered_public_examples": sum(1 for r in rows if r["group"]=="registered-public"), "optional_public_issue_examples": sum(1 for r in rows if r["group"]=="optional-public-issue"), "provider_drift_examples": sum(1 for r in rows if r["group"]=="provider-drift"), "metadata_valid": ok, "hosts": sorted({r['url_host'] for r in rows}), "hash_algorithm": "sha256-normalized-json"}
    (out/"public_source_metadata_overall.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
    print(json.dumps(manifest, indent=2))
    return 0 if ok else 1
if __name__ == "__main__":
    raise SystemExit(main())
