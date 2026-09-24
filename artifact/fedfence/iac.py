"""Infrastructure-as-code extraction helpers for FedFence."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

@dataclass
class ExtractedRole:
    source: str
    role_name: str
    format: str
    case: Dict[str, Any]
    expected_safe: Optional[bool] = None
    expected_template: Optional[str] = None

def _loads_json_maybe(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value

def _split_patterns(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    text = str(value)
    return [v for v in text.split("\n") if v]

def _loads_json_array_maybe(value: Any) -> List[Any]:
    if value is None:
        return []
    obj = json.loads(value) if isinstance(value, str) else value
    return obj if isinstance(obj, list) else []


def _bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "safe"}:
        return True
    if s in {"0", "false", "no", "unsafe"}:
        return False
    return None

def _case_from_parts(name: str, policy: Mapping[str, Any], meta: Mapping[str, Any]) -> Dict[str, Any]:
    subjects = _split_patterns(meta.get("FedFenceIntentSubjects") or meta.get("intent_subjects"))
    subject_globs = _split_patterns(meta.get("FedFenceIntentSubjectGlobs") or meta.get("intent_subject_globs"))
    audiences = _split_patterns(meta.get("FedFenceIntentAudiences") or meta.get("intent_audiences"))
    audience_globs = _split_patterns(meta.get("FedFenceIntentAudienceGlobs") or meta.get("intent_audience_globs"))
    issuer = _split_patterns(meta.get("FedFenceIssuerSubjects") or meta.get("issuer_subjects"))
    protected_envs = _split_patterns(meta.get("FedFenceProtectedEnvironments") or meta.get("protected_environments"))
    states = _loads_json_array_maybe(meta.get("FedFenceStates") or meta.get("states"))
    spec: Dict[str, Any] = {
        "allowed_subjects": subjects,
        "allowed_audiences": audiences or ["sts.amazonaws.com"],
    }
    if subject_globs:
        spec["allowed_subject_globs"] = subject_globs
    if audience_globs:
        spec["allowed_audience_globs"] = audience_globs
    if issuer:
        spec["issuer_subjects"] = issuer
    case = {"name": name, "policy": dict(policy), "spec": spec,
            "repository_governance": {"protected_environments": protected_envs}}
    if states:
        case["states"] = states
    return case

def _extract_direct(path: Path, obj: Mapping[str, Any]) -> Iterator[ExtractedRole]:
    if "policy" not in obj:
        return
    case = dict(obj); name = str(case.get("name", path.stem))
    yield ExtractedRole(str(path), name, "direct-json", case, _bool(case.get("expected_safe")),
                        str(case.get("expected_template")) if case.get("expected_template") else None)

def _extract_terraform_json(path: Path, obj: Mapping[str, Any]) -> Iterator[ExtractedRole]:
    resources = obj.get("resource", {})
    if not isinstance(resources, Mapping):
        return
    roles = resources.get("aws_iam_role", {})
    if not isinstance(roles, Mapping):
        return
    for role_name, body in roles.items():
        if not isinstance(body, Mapping) or body.get("assume_role_policy") is None:
            continue
        tags = body.get("tags", {}) or {}
        if not isinstance(tags, Mapping):
            tags = {}
        case = _case_from_parts(str(role_name), _loads_json_maybe(body["assume_role_policy"]), tags)
        yield ExtractedRole(str(path), str(role_name), "terraform-json", case,
                            _bool(tags.get("FedFenceExpectedSafe")),
                            str(tags.get("FedFenceTemplate")) if tags.get("FedFenceTemplate") else None)

def _extract_cloudformation_json(path: Path, obj: Mapping[str, Any], fmt: str) -> Iterator[ExtractedRole]:
    resources = obj.get("Resources", {})
    if not isinstance(resources, Mapping):
        return
    for role_name, res in resources.items():
        if not isinstance(res, Mapping) or res.get("Type") != "AWS::IAM::Role":
            continue
        props = res.get("Properties", {}) or {}
        if not isinstance(props, Mapping) or props.get("AssumeRolePolicyDocument") is None:
            continue
        meta = res.get("Metadata", {}) or {}
        if not isinstance(meta, Mapping):
            meta = {}
        case = _case_from_parts(str(role_name), _loads_json_maybe(props["AssumeRolePolicyDocument"]), meta)
        yield ExtractedRole(str(path), str(role_name), fmt, case, _bool(meta.get("FedFenceExpectedSafe")),
                            str(meta.get("FedFenceTemplate")) if meta.get("FedFenceTemplate") else None)


def _hcl_unquote(value: str) -> str:
    """Decode a minimal Terraform quoted string used by frontier fixtures."""
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return json.loads(value)
    return value


def _find_hcl_resource_blocks(text: str) -> Iterator[tuple[str, str]]:
    """Yield aws_iam_role resource blocks from simple Terraform HCL.

    This is intentionally a small extractor, not a full Terraform interpreter: it
    supports the concrete review-packet shape used by the artifact (a role with a
    string-valued ``assume_role_policy`` and string tags carrying FedFence intent
    metadata).  Unsupported dynamic Terraform expressions simply produce no role,
    preventing them from being certified accidentally.
    """
    pat = re.compile(r'resource\s+"aws_iam_role"\s+"([^"]+)"\s*\{')
    for m in pat.finditer(text):
        name = m.group(1)
        i = m.end() - 1
        depth = 0
        in_str = False
        esc = False
        end = None
        for j in range(i, len(text)):
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end is not None:
            yield name, text[i+1:end]


def _parse_hcl_tags(block: str) -> Dict[str, str]:
    m = re.search(r'tags\s*=\s*\{', block)
    if not m:
        return {}
    i = m.end() - 1
    depth = 0
    in_str = False
    esc = False
    end = None
    for j in range(i, len(block)):
        ch = block[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = j
                break
    if end is None:
        return {}
    body = block[i+1:end]
    tags: Dict[str, str] = {}
    for key, raw in re.findall(r'([A-Za-z0-9_]+)\s*=\s*("(?:[^"\\]|\\.)*")', body):
        tags[key] = _hcl_unquote(raw)
    return tags


def _extract_terraform_hcl(path: Path, text: str) -> Iterator[ExtractedRole]:
    for role_name, block in _find_hcl_resource_blocks(text):
        m = re.search(r'assume_role_policy\s*=\s*("(?:[^"\\]|\\.)*")', block, re.S)
        if not m:
            continue
        try:
            policy = json.loads(_hcl_unquote(m.group(1)))
        except Exception:
            continue
        tags = _parse_hcl_tags(block)
        case = _case_from_parts(str(role_name), policy, tags)
        yield ExtractedRole(str(path), str(role_name), "terraform-hcl", case,
                            _bool(tags.get("FedFenceExpectedSafe")),
                            str(tags.get("FedFenceTemplate")) if tags.get("FedFenceTemplate") else None)


def extract_file(path: Path) -> List[ExtractedRole]:
    suffixes = "".join(path.suffixes).lower()
    if path.suffix.lower() == ".tf" and not suffixes.endswith(".tf.json"):
        return list(_extract_terraform_hcl(path, path.read_text()))
    if suffixes.endswith(".json") or suffixes.endswith(".tf.json") or suffixes.endswith(".cfn.json"):
        obj = json.loads(path.read_text())
    elif path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML/CloudFormation files; install artifact/requirements.txt")
        obj = yaml.safe_load(path.read_text())
    else:
        return []
    if not isinstance(obj, Mapping):
        return []
    out: List[ExtractedRole] = []
    out.extend(_extract_direct(path, obj))
    out.extend(_extract_terraform_json(path, obj))
    fmt = "cloudformation-json" if path.suffix.lower() == ".json" else "cloudformation-yaml"
    out.extend(_extract_cloudformation_json(path, obj, fmt))
    return out

def extract_tree(root: Path) -> Iterator[ExtractedRole]:
    for p in sorted(root.rglob("*")):
        if p.is_file():
            for role in extract_file(p):
                yield role
