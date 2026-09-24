#!/usr/bin/env python3
from __future__ import annotations
import csv, json, statistics, sys, time
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case  # noqa: E402

ORG = "acme"
AUD = "sts.amazonaws.com"
PRINC = {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"}

def subject(repo: str, kind: str = "branch", value: str = "main") -> str:
    if kind == "branch":
        return f"repo:{ORG}/{repo}:ref:refs/heads/{value}"
    if kind == "tag":
        return f"repo:{ORG}/{repo}:ref:refs/tags/{value}"
    if kind == "pr":
        return f"repo:{ORG}/{repo}:pull_request"
    if kind == "env":
        return f"repo:{ORG}/{repo}:environment:{value}"
    raise ValueError(kind)

def stmt(sub: Any, aud: Any = AUD, *, sub_like: bool = False, aud_like: bool = False, effect: str = "Allow", principal: Any = None, action: Any = "sts:AssumeRoleWithWebIdentity", extra: dict[str, Any] | None = None) -> Dict[str, Any]:
    cond: dict[str, dict[str, Any]] = {}
    if sub is not None:
        cond.setdefault("StringLike" if sub_like else "StringEquals", {})["token.actions.githubusercontent.com:sub"] = sub
    if aud is not None:
        cond.setdefault("StringLike" if aud_like else "StringEquals", {})["token.actions.githubusercontent.com:aud"] = aud
    if extra:
        for op, kv in extra.items():
            cond.setdefault(op, {}).update(kv)
    return {"Effect": effect, "Principal": principal or PRINC, "Action": action, "Condition": cond}

def policy(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}

def base(repo: str) -> dict[str, Any]:
    return {"allowed_subjects": [subject(repo)], "allowed_audiences": [AUD]}

def case(name: str, repo: str, st: dict[str, Any], expected: bool, *, spec: dict[str, Any] | None = None, gov: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"name": f"adv_{name}_{repo}", "policy": policy(st), "spec": spec or base(repo), "repository_governance": gov or {"protected_environments": []}, "expected_safe": expected}

Family = Callable[[str], Tuple[dict[str, Any], bool]]

def families() -> dict[str, Family]:
    def exact(repo): return case("exact", repo, stmt(subject(repo), AUD), True), True
    def suffix(repo): return case("suffix", repo, stmt(f"repo:{ORG}/{repo}:*", AUD, sub_like=True), False), False
    def org(repo): return case("org", repo, stmt(f"repo:{ORG}/*:ref:refs/heads/main", AUD, sub_like=True), False), False
    def tag(repo): return case("tag", repo, stmt(subject(repo, "tag", "v*"), AUD, sub_like=True), False), False
    def pr(repo): return case("pr", repo, stmt(subject(repo, "pr"), AUD), False), False
    def audwild(repo): return case("audwild", repo, stmt(subject(repo), "*", aud_like=True), False), False
    def literal_star(repo): return case("litstar", repo, stmt(subject(repo), "*"), False), False
    def qmark_subject(repo): return case("qmark", repo, stmt(subject(repo, "branch", "release?"), AUD), True, spec={"allowed_subjects":[subject(repo, "branch", "release?")], "allowed_audiences":[AUD]}), True
    def unsupported_allow(repo): return case("unsupportedallow", repo, stmt(subject(repo), AUD, extra={"StringEquals":{"aws:PrincipalTag/team":"release"}}), True), True
    def action_wild(repo): return case("actionwild", repo, stmt(subject(repo), AUD, action="*"), False), False
    def mixed_principal(repo): return case("mixedprincipal", repo, stmt(subject(repo), AUD, principal={"Federated": PRINC["Federated"], "AWS": "arn:aws:iam::000000000000:root"}), False), False
    def substring_principal(repo): return case("substringprincipal", repo, stmt(subject(repo), AUD, principal={"Federated":"arn:aws:iam::000000000000:oidc-provider/not-token.actions.githubusercontent.com"}), False), False
    def unqualified(repo):
        s = stmt(None, None); s["Condition"] = {"StringEquals":{"sub":subject(repo), "aud":AUD}}
        return case("unqualified", repo, s, False), False
    def safe_deny(repo):
        allow = stmt(subject(repo), AUD)
        deny = stmt(subject(repo, "branch", "dev"), AUD, effect="Deny")
        return {"name": f"adv_safedeny_{repo}", "policy": policy(allow, deny), "spec": base(repo), "repository_governance":{"protected_environments":[]}, "expected_safe": True}, True
    def broad_deny(repo):
        allow = stmt(subject(repo, "branch", "*"), AUD, sub_like=True)
        deny = stmt(subject(repo, "branch", "dev"), AUD, effect="Deny", extra={"StringEquals":{"aws:PrincipalTag/team":"release"}})
        return {"name": f"adv_unsupdeny_{repo}", "policy": policy(allow, deny), "spec": base(repo), "repository_governance":{"protected_environments":[]}, "expected_safe": False}, False
    def env_safe(repo):
        env = subject(repo, "env", "prod")
        return case("envsafe", repo, stmt(env, AUD), True, spec={"allowed_subjects":[env],"allowed_audiences":[AUD]}, gov={"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod"}]}), True
    def env_cross(repo):
        env = subject(repo, "env", "prod")
        return case("envcross", repo, stmt(env, AUD), False, spec={"allowed_subjects":[env],"allowed_audiences":[AUD]}, gov={"protected_environments":[{"owner":ORG,"repository":repo+"x","environment":"prod"}]}), False
    def forany(repo):
        st = stmt(None, None, extra={"ForAnyValue:StringEquals":{"token.actions.githubusercontent.com:sub":subject(repo),"token.actions.githubusercontent.com:aud":AUD}})
        return case("forany", repo, st, False), False
    def forall(repo):
        st = stmt(None, None, extra={"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":f"repo:{ORG}/{repo}:*","token.actions.githubusercontent.com:aud":AUD}})
        return case("forall", repo, st, False), False
    def ifexists(repo):
        st = stmt(None, None, extra={"StringEqualsIfExists":{"token.actions.githubusercontent.com:sub":subject(repo),"token.actions.githubusercontent.com:aud":AUD}})
        return case("ifexists", repo, st, False), False
    def notaction(repo):
        s = stmt(subject(repo), AUD); s.pop("Action", None); s["NotAction"] = "sts:AssumeRole"
        return case("notaction", repo, s, False), False
    def action_multi(repo):
        return case("actionmulti", repo, stmt(subject(repo), AUD, action=["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]), False), False
    def notprincipal(repo):
        s = stmt(subject(repo), AUD); s.pop("Principal", None); s["NotPrincipal"] = {"AWS":"arn:aws:iam::111111111111:root"}
        return case("notprincipal", repo, s, False), False
    def malformed_principal(repo):
        return case("malformedprincipal", repo, stmt(subject(repo), AUD, principal={"Federated":"token.actions.githubusercontent.com"}), False), False
    def condition_not_mapping(repo):
        s = stmt(subject(repo), AUD); s["Condition"] = ["not-a-map"]
        return case("badcondition", repo, s, False), False
    def missing_audience(repo):
        return case("missingaud", repo, stmt(subject(repo), None), False), False
    def aud_list_broad(repo):
        return case("audlist", repo, stmt(subject(repo), [AUD, "vault.example"]), False), False
    def sub_list_broad(repo):
        return case("sublist", repo, stmt([subject(repo), subject(repo, "branch", "dev")], AUD), False), False
    def env_wildcard(repo):
        return case("envwild", repo, stmt(f"repo:{ORG}/{repo}:environment:*", AUD, sub_like=True), False, spec={"allowed_subjects":[subject(repo,"env","prod")],"allowed_audiences":[AUD]}, gov={"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod"}]}), False
    def exact_tag_safe(repo):
        return case("tagsafe", repo, stmt(subject(repo, "tag", "v1.0.0"), AUD), True, spec={"allowed_subjects":[subject(repo,"tag","v1.0.0")],"allowed_audiences":[AUD]}), True
    def split_safe(repo):
        st1 = stmt(subject(repo, "branch", "main"), AUD); st2 = stmt(subject(repo, "branch", "release"), AUD)
        return {"name":f"adv_splitsafe_{repo}","policy":policy(st1,st2),"spec":{"allowed_subjects":[subject(repo,"branch","main"),subject(repo,"branch","release")],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[]},"expected_safe":True}, True
    def split_broad(repo):
        st1 = stmt(subject(repo), AUD); st2 = stmt(f"repo:{ORG}/{repo}:*", AUD, sub_like=True)
        return {"name":f"adv_splitbroad_{repo}","policy":policy(st1,st2),"spec":base(repo),"repository_governance":{"protected_environments":[]},"expected_safe":False}, False
    def foreign_key(repo):
        s = stmt(None, AUD); s["Condition"].setdefault("StringEquals", {})["evil.example:sub"] = subject(repo)
        return case("foreignkey", repo, s, False), False
    def arnlike(repo):
        s = stmt(None, None, extra={"ArnLike":{"token.actions.githubusercontent.com:sub":subject(repo),"token.actions.githubusercontent.com:aud":AUD}})
        return case("arnlike", repo, s, True), True
    def arnequals_question(repo):
        return case("arneqq", repo, stmt(subject(repo,"branch","release?"), AUD, extra=None), True, spec={"allowed_subjects":[subject(repo,"branch","release?")],"allowed_audiences":[AUD]}), True
    return {name: fn for name, fn in locals().items() if callable(fn)}

def main() -> int:
    import os
    per = int(os.environ.get("FEDFENCE_ADV_PER", "64"))
    def has_sub_aud(c: dict[str, Any]) -> bool:
        for st in c.get("policy", {}).get("Statement", []):
            seen_sub = seen_aud = False
            cond = st.get("Condition", {}) if isinstance(st, dict) else {}
            if isinstance(cond, dict):
                for kv in cond.values():
                    if isinstance(kv, dict):
                        for k in kv:
                            seen_sub |= str(k).endswith(":sub") or str(k) == "sub"
                            seen_aud |= str(k).endswith(":aud") or str(k) == "aud"
            if seen_sub and seen_aud:
                return True
        return False
    def no_wild(c: dict[str, Any]) -> bool:
        text = json.dumps(c.get("policy", {}), sort_keys=True)
        return "*" not in text and "?" not in text and has_sub_aud(c)
    def exact_env(c: dict[str, Any]) -> bool:
        text = json.dumps(c.get("policy", {}), sort_keys=True)
        return no_wild(c) or ":environment:" in text
    rows = []
    fams = families()
    for fname, fn in sorted(fams.items()):
        for i in range(per):
            repo = f"adv{i:03d}"
            c, expected = fn(repo)
            t0 = time.perf_counter(); res = analyze_case(c); ms = (time.perf_counter() - t0) * 1000
            rows.append({"family": fname, "atom": i, "expected_safe": expected, "fedfence_safe": bool(res.safe), "correct": bool(res.safe) == bool(expected), "presence_safe":has_sub_aud(c), "nowild_safe":no_wild(c), "exactenv_safe":exact_env(c), "findings": ";".join(f.kind for f in res.findings), "ms": round(ms, 3)})
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with (out / "adversarial_matrix.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    summary=[]
    for fname in sorted(fams):
        rs=[r for r in rows if r["family"]==fname]
        summary.append({"family":fname,"n":len(rs),"safe_expected":sum(1 for r in rs if r["expected_safe"]),"unsafe_expected":sum(1 for r in rs if not r["expected_safe"]),"correct":sum(1 for r in rs if r["correct"]),"median_ms":round(statistics.median(float(r["ms"]) for r in rs),3),"p95_ms":round(statistics.quantiles([float(r["ms"]) for r in rs],n=20)[18],3)})
    with (out / "adversarial_matrix_summary.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    def metrics(name: str, field: str) -> dict[str, Any]:
        tp=tn=fp=fn=0
        for r in rows:
            expected_safe=bool(r["expected_safe"]); pred_safe=bool(r[field])
            if not expected_safe and not pred_safe: tp += 1
            elif expected_safe and pred_safe: tn += 1
            elif expected_safe and not pred_safe: fp += 1
            else: fn += 1
        return {"analyzer": name, "tp_unsafe":tp, "tn_safe":tn, "false_alarm":fp, "miss":fn,
                "unsafe_recall": round(tp/(tp+fn),4) if tp+fn else 1.0,
                "unsafe_precision": round(tp/(tp+fp),4) if tp+fp else 1.0,
                "safe_acceptance": round(tn/(tn+fp),4) if tn+fp else 1.0}
    base_rows=[metrics("FedFence","fedfence_safe"), metrics("Presence","presence_safe"), metrics("NoWildcard","nowild_safe"), metrics("ExactEnv","exactenv_safe")]
    with (out / "adversarial_baselines.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(base_rows[0].keys())); w.writeheader(); w.writerows(base_rows)
    overall={"families":len(fams),"per_family":per,"total_cases":len(rows),"correct":sum(1 for r in rows if r["correct"]),"unsafe_cases":sum(1 for r in rows if not r["expected_safe"]),"median_ms":round(statistics.median(float(r["ms"]) for r in rows),3),"p95_ms":round(statistics.quantiles([float(r["ms"]) for r in rows],n=20)[18],3),"baseline_rows":len(base_rows)}
    (out / "adversarial_matrix_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True)+"\n")
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if overall["correct"] == overall["total_cases"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
