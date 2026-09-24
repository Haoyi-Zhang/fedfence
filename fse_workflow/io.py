"""Strict JSON and deterministic digest helpers. Hashes are not authentication."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"nonfinite number: {x}")))


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def save_json(path: str | Path, obj: Any):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False,
                               allow_nan=False) + "\n", encoding="utf-8")
