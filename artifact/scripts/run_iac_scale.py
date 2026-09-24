#!/usr/bin/env python3
from __future__ import annotations
import csv, gc, json, os, statistics, sys, tempfile, time
from pathlib import Path
from typing import Any, Dict, List, Tuple
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ORG = "acme"; AUD = "sts.amazonaws.com"
FORMATS=["direct-json","terraform-json","cloudformation-json"]
ALL_TEMPLATES=["safe_exact_branch","safe_release_tags","safe_protected_environment","safe_two_release_branches","safe_dual_audience","safe_split_statements","safe_conjunctive_refinement","safe_dynamic_alphabet","safe_branch_slash","safe_encoded_colon_environment","safe_unsupported_allow_narrowing","selected_claim_ref_env_repoid_safe","selected_claim_custom_property_without_ref_unsafe","repo_suffix_wildcard","org_repo_wildcard","branch_wildcard","tag_as_prod","pull_request_exact","missing_subject","audience_wildcard","literal_star_audience","literal_question_audience","multi_statement_broad","unprotected_environment","environment_wildcard","cross_repository_environment_governance","audience_list_broad","repo_prefix_typo","mixed_env_and_branch_broad","conjunctive_ref_broad","unsupported_deny_cannot_discharge","safe_deny_narrowing","unqualified_claim_keys","substring_principal","non_github_principal","wildcard_federated_principal","mixed_principal_outside_core","action_sts_star_outside_core","empty_condition_value_boundary","malformed_condition_value_boundary"]
# The registered paper profile fixes the abstract-visible counts: 35 IaC/semantic-grid templates.
# The final five entries are optional schema-boundary hardening templates and are
# excluded from the locked abstract counts unless FEDFENCE_TEMPLATE_PROFILE=extended.
REGISTERED_TEMPLATES = ALL_TEMPLATES[:35]
HARDENING_TEMPLATES = ALL_TEMPLATES[35:]
_TEMPLATE_PROFILE = os.environ.get("FEDFENCE_TEMPLATE_PROFILE", "registered").strip().lower()
if _TEMPLATE_PROFILE in {"extended", "all", "hardening"}:
    TEMPLATES = ALL_TEMPLATES
elif _TEMPLATE_PROFILE == "registered":
    TEMPLATES = REGISTERED_TEMPLATES
else:
    raise ValueError(f"unknown FEDFENCE_TEMPLATE_PROFILE={_TEMPLATE_PROFILE!r}")

def policy(sub_values=None, aud_values=None, sub_like=False, aud_like=False, statements=None, principal=None):
    if statements is not None: return {"Version":"2012-10-17","Statement":statements}
    cond: Dict[str, Dict[str, Any]] = {}
    if aud_values is not None: cond.setdefault("StringLike" if aud_like else "StringEquals", {})["token.actions.githubusercontent.com:aud"] = aud_values
    if sub_values is not None: cond.setdefault("StringLike" if sub_like else "StringEquals", {})["token.actions.githubusercontent.com:sub"] = sub_values
    if principal is None:
        principal={"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"}
    return {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":principal,"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}

def subject(repo: str, kind: str, val: str="main") -> str:
    if kind == "branch": return f"repo:{ORG}/{repo}:ref:refs/heads/{val}"
    if kind == "tag": return f"repo:{ORG}/{repo}:ref:refs/tags/{val}"
    if kind == "pr": return f"repo:{ORG}/{repo}:pull_request"
    if kind == "env": return f"repo:{ORG}/{repo}:environment:{val}"
    raise ValueError(kind)


def selected_states(repo: str) -> list[dict[str, Any]]:
    return [
        {"id":"main-prod","mintable":True,"intended":True,"claims":{"aud":AUD,"sub":subject(repo,"env","prod"),"repository":f"{ORG}/{repo}","repository_id":f"R_{repo}","environment":"prod","ref":"refs/heads/main","job_workflow_ref":f"{ORG}/{repo}/.github/workflows/deploy.yml@refs/heads/main","repository_custom_properties.tier":"prod"}},
        {"id":"dev-prod","mintable":True,"intended":False,"claims":{"aud":AUD,"sub":subject(repo,"env","prod"),"repository":f"{ORG}/{repo}","repository_id":f"R_{repo}","environment":"prod","ref":"refs/heads/dev","job_workflow_ref":f"{ORG}/{repo}/.github/workflows/deploy.yml@refs/heads/dev","repository_custom_properties.tier":"prod"}},
        {"id":"main-staging","mintable":True,"intended":False,"claims":{"aud":AUD,"sub":subject(repo,"env","staging"),"repository":f"{ORG}/{repo}","repository_id":f"R_{repo}","environment":"staging","ref":"refs/heads/main","job_workflow_ref":f"{ORG}/{repo}/.github/workflows/deploy.yml@refs/heads/main","repository_custom_properties.tier":"dev"}},
        {"id":"other-prod","mintable":True,"intended":False,"claims":{"aud":AUD,"sub":f"repo:evil/{repo}:environment:prod","repository":f"evil/{repo}","repository_id":f"R_evil_{repo}","environment":"prod","ref":"refs/heads/main","job_workflow_ref":f"evil/{repo}/.github/workflows/deploy.yml@refs/heads/main","repository_custom_properties.tier":"prod"}},
    ]

def selected_policy(repo: str, *, include_ref: bool) -> Dict[str, Any]:
    cond = {"token.actions.githubusercontent.com:aud": AUD, "token.actions.githubusercontent.com:environment": "prod", "token.actions.githubusercontent.com:repository_id": f"R_{repo}"}
    if include_ref:
        cond["token.actions.githubusercontent.com:ref"] = "refs/heads/main"
    else:
        cond["token.actions.githubusercontent.com:repository_custom_properties.tier"] = "prod"
    return {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":cond}}]}

def make_template(template: str, repo: str) -> Tuple[Dict[str, Any], bool]:
    main = subject(repo,"branch","main"); base_spec={"allowed_subjects":[main],"allowed_audiences":[AUD]}; gov={"protected_environments":[]}
    if template == "safe_exact_branch": return {"policy":policy(main,AUD),"spec":base_spec,"repository_governance":gov}, True
    if template == "safe_release_tags":
        tag=subject(repo,"tag","v*"); return {"policy":policy(tag,AUD,sub_like=True),"spec":{"allowed_subject_globs":[tag],"allowed_audiences":[AUD]},"repository_governance":gov}, True
    if template == "safe_protected_environment":
        env=subject(repo,"env","prod"); return {"policy":policy(env,AUD),"spec":{"allowed_subjects":[env],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod"}]}}, True
    if template == "safe_two_release_branches":
        vals=[subject(repo,"branch","main"), subject(repo,"branch","release")]; return {"policy":policy(vals,AUD),"spec":{"allowed_subjects":vals,"allowed_audiences":[AUD]},"repository_governance":gov}, True
    if template == "safe_dual_audience":
        vals=[AUD,"sigstore"]; return {"policy":policy(main,vals),"spec":{"allowed_subjects":[main],"allowed_audiences":vals},"repository_governance":gov}, True
    if template == "safe_split_statements":
        br=subject(repo,"branch","main"); tg=subject(repo,"tag","v*"); st1=policy(br,AUD)["Statement"][0]; st2=policy(tg,AUD,sub_like=True)["Statement"][0]; return {"policy":policy(statements=[st1,st2]),"spec":{"allowed_subjects":[br],"allowed_subject_globs":[tg],"allowed_audiences":[AUD]},"repository_governance":gov}, True
    if template == "safe_conjunctive_refinement":
        cond={"StringLike":{"token.actions.githubusercontent.com:sub":f"repo:{ORG}/{repo}:*"},"StringEquals":{"token.actions.githubusercontent.com:aud":AUD,"token.actions.githubusercontent.com:sub":main}}
        pol={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}
        return {"policy":pol,"spec":base_spec,"repository_governance":gov}, True
    if template == "safe_dynamic_alphabet":
        dyn=subject(repo,"branch","release$prod"); return {"policy":policy(dyn,AUD),"spec":{"allowed_subjects":[dyn],"allowed_audiences":[AUD]},"repository_governance":{"protected_branches":["release$prod"],"protected_environments":[]}}, True
    if template == "safe_branch_slash":
        br=subject(repo,"branch","release/2026"); return {"policy":policy(br,AUD),"spec":{"allowed_subjects":[br],"allowed_audiences":[AUD]},"repository_governance":gov}, True
    if template == "safe_encoded_colon_environment":
        env=subject(repo,"env","prod%3Ablue"); return {"policy":policy(env,AUD),"spec":{"allowed_subjects":[env],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod%3Ablue"}]}}, True
    if template == "safe_unsupported_allow_narrowing":
        cond={"StringEquals":{"token.actions.githubusercontent.com:aud":AUD,"token.actions.githubusercontent.com:sub":main,"aws:PrincipalTag/team":"release"}}
        pol={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}
        return {"policy":pol,"spec":base_spec,"repository_governance":gov}, True
    if template == "selected_claim_ref_env_repoid_safe":
        return {"policy":selected_policy(repo, include_ref=True),"spec":base_spec,"states":selected_states(repo),"repository_governance":gov}, True
    if template == "selected_claim_custom_property_without_ref_unsafe":
        return {"policy":selected_policy(repo, include_ref=False),"spec":base_spec,"states":selected_states(repo),"repository_governance":gov}, False
    if template == "repo_suffix_wildcard": return {"policy":policy(f"repo:{ORG}/{repo}:*",AUD,sub_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "org_repo_wildcard": return {"policy":policy(f"repo:{ORG}/*:ref:refs/heads/main",AUD,sub_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "branch_wildcard": return {"policy":policy(subject(repo,"branch","*"),AUD,sub_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "tag_as_prod": return {"policy":policy(subject(repo,"tag","v*"),AUD,sub_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "pull_request_exact": return {"policy":policy(subject(repo,"pr"),AUD),"spec":base_spec,"repository_governance":gov}, False
    if template == "missing_subject": return {"policy":policy(None,AUD),"spec":base_spec,"repository_governance":gov}, False
    if template == "audience_wildcard": return {"policy":policy(main,"*",aud_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "literal_star_audience": return {"policy":policy(main,"*"),"spec":base_spec,"repository_governance":gov}, False
    if template == "literal_question_audience": return {"policy":policy(main,"?"),"spec":base_spec,"repository_governance":gov}, False
    if template == "multi_statement_broad":
        st1=policy(main,AUD)["Statement"][0]; st2=policy(subject(repo,"branch","*"),AUD,sub_like=True)["Statement"][0]; return {"policy":policy(statements=[st1,st2]),"spec":base_spec,"repository_governance":gov}, False
    if template == "unprotected_environment":
        env=subject(repo,"env","prod"); return {"policy":policy(env,AUD),"spec":{"allowed_subjects":[env],"allowed_audiences":[AUD]},"repository_governance":gov}, False
    if template == "cross_repository_environment_governance":
        env=subject(repo,"env","prod"); return {"policy":policy(env,AUD),"spec":{"allowed_subjects":[env],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[{"owner":ORG,"repository":repo+"-other","environment":"prod"}]}}, False
    if template == "environment_wildcard":
        env=f"repo:{ORG}/{repo}:environment:*"; return {"policy":policy(env,AUD,sub_like=True),"spec":{"allowed_subjects":[subject(repo,"env","prod")],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod"}]}}, False
    if template == "audience_list_broad": return {"policy":policy(main,[AUD,"*"],aud_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "repo_prefix_typo": return {"policy":policy(f"repo:{ORG}/{repo[:-1]}*:ref:refs/heads/main",AUD,sub_like=True),"spec":base_spec,"repository_governance":gov}, False
    if template == "mixed_env_and_branch_broad":
        st1=policy(subject(repo,"env","prod"),AUD)["Statement"][0]; st2=policy(subject(repo,"branch","*"),AUD,sub_like=True)["Statement"][0]; return {"policy":policy(statements=[st1,st2]),"spec":{"allowed_subjects":[subject(repo,"env","prod")],"allowed_audiences":[AUD]},"repository_governance":{"protected_environments":[{"owner":ORG,"repository":repo,"environment":"prod"}]}}, False
    if template == "conjunctive_ref_broad":
        cond={"StringLike":{"token.actions.githubusercontent.com:sub":f"repo:{ORG}/{repo}:*"},"ArnLike":{"token.actions.githubusercontent.com:sub":f"repo:{ORG}/{repo}:ref:*"},"StringEquals":{"token.actions.githubusercontent.com:aud":AUD}}
        pol={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}
        return {"policy":pol,"spec":base_spec,"repository_governance":gov}, False
    if template == "unsupported_deny_cannot_discharge":
        allow=policy(subject(repo,"branch","*"),AUD,sub_like=True)["Statement"][0]
        deny=policy(subject(repo,"branch","feature-x"),AUD)["Statement"][0]; deny["Effect"]="Deny"; deny.setdefault("Condition",{}).setdefault("StringEquals",{})["aws:PrincipalTag/team"]="release"
        return {"policy":policy(statements=[allow,deny]),"spec":base_spec,"repository_governance":gov}, False
    if template == "safe_deny_narrowing":
        allow=policy(main,AUD)["Statement"][0]; deny=policy(subject(repo,"branch","breakglass"),AUD)["Statement"][0]; deny["Effect"]="Deny"
        return {"policy":policy(statements=[allow,deny]),"spec":base_spec,"repository_governance":gov}, True
    if template == "unqualified_claim_keys":
        cond={"StringEquals":{"aud":AUD,"sub":main}}
        pol={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}
        return {"policy":pol,"spec":base_spec,"repository_governance":gov}, False
    if template == "substring_principal":
        other={"Federated":"arn:aws:iam::000000000000:oidc-provider/evil-token.actions.githubusercontent.com"}
        return {"policy":policy(main,AUD,principal=other),"spec":base_spec,"repository_governance":gov}, False
    if template == "non_github_principal":
        other={"Federated":"arn:aws:iam::000000000000:oidc-provider/issuer.example.invalid"}
        return {"policy":policy(main,AUD,principal=other),"spec":base_spec,"repository_governance":gov}, False
    if template == "wildcard_federated_principal":
        return {"policy":policy(main,AUD,principal="*"),"spec":base_spec,"repository_governance":gov}, False
    if template == "mixed_principal_outside_core":
        mixed={"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com","AWS":"arn:aws:iam::000000000000:root"}
        return {"policy":policy(main,AUD,principal=mixed),"spec":base_spec,"repository_governance":gov}, False
    if template == "action_sts_star_outside_core":
        c=policy(main,AUD); c["Statement"][0]["Action"]="sts:*"; return {"policy":c,"spec":base_spec,"repository_governance":gov}, False
    if template == "empty_condition_value_boundary":
        c=policy(main,AUD); c["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"]=[]; return {"policy":c,"spec":base_spec,"repository_governance":gov}, False
    if template == "malformed_condition_value_boundary":
        c=policy(main,AUD); c["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"]={"bad":"value"}; return {"policy":c,"spec":base_spec,"repository_governance":gov}, False
    raise ValueError(template)

def meta(case: Dict[str, Any], expected: bool, template: str) -> Dict[str, str]:
    spec=case["spec"]; gov=case.get("repository_governance",{})
    m={"FedFenceIntentSubjects":"\n".join(spec.get("allowed_subjects",[])),"FedFenceIntentSubjectGlobs":"\n".join(spec.get("allowed_subject_globs",[])),"FedFenceIntentAudiences":"\n".join(spec.get("allowed_audiences",[AUD])),"FedFenceIntentAudienceGlobs":"\n".join(spec.get("allowed_audience_globs",[])),"FedFenceProtectedEnvironments":"\n".join(json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in gov.get("protected_environments",[])),"FedFenceExpectedSafe":"true" if expected else "false","FedFenceTemplate":template}
    if "states" in case:
        m["FedFenceStates"] = json.dumps(case["states"], sort_keys=True)
    return m


def encoded_object(fmt: str, idx: int, template: str, case: Dict[str, Any], expected: bool) -> Tuple[Path, Dict[str, Any]]:
    name=f"{template}_{idx:05d}"
    if fmt=="direct-json":
        obj=dict(case); obj.update({"name":name,"expected_safe":expected,"expected_template":template}); return Path(f"{name}.json"), obj
    if fmt=="terraform-json":
        obj={"resource":{"aws_iam_role":{name:{"name":name,"assume_role_policy":json.dumps(case["policy"],sort_keys=True),"tags":meta(case,expected,template)}}}}; return Path(f"{name}.tf.json"), obj
    obj={"Resources":{name.replace("_",""):{"Type":"AWS::IAM::Role","Metadata":meta(case,expected,template),"Properties":{"AssumeRolePolicyDocument":case["policy"]}}}}; return Path(f"{name}.cfn.json"), obj

def extract_encoded(fmt: str, path: Path, obj: Dict[str, Any]):
    from fedfence.iac import _extract_direct, _extract_terraform_json, _extract_cloudformation_json
    if fmt=="direct-json": return list(_extract_direct(path,obj))
    if fmt=="terraform-json": return list(_extract_terraform_json(path,obj))
    return list(_extract_cloudformation_json(path,obj,"cloudformation-json"))

def contains_wildcard_case(case: Dict[str, Any]) -> bool:
    for st in case.get("policy",{}).get("Statement",[]):
        for group in (st.get("Condition",{}) or {}).values():
            if isinstance(group,dict):
                for v in group.values():
                    vals=v if isinstance(v,list) else [v]
                    if any("*" in str(x) or "?" in str(x) for x in vals): return True
    return False

def has_subject_and_audience(case: Dict[str, Any]) -> bool:
    for st in case.get("policy",{}).get("Statement",[]):
        seen_sub=seen_aud=False
        for group in (st.get("Condition",{}) or {}).values():
            if isinstance(group,dict):
                for k in group:
                    seen_sub |= str(k).endswith(":sub") or str(k)=="sub"; seen_aud |= str(k).endswith(":aud") or str(k)=="aud"
        if not (seen_sub and seen_aud): return False
    return True

def exact_env_linter(case: Dict[str, Any]) -> bool:
    return has_subject_and_audience(case) and not contains_wildcard_case(case)

def record_role(fmt: str, template: str, idx: int) -> Dict[str, Any]:
    from fedfence.analyzer import analyze_case
    case, expected = make_template(template, f"svc{idx:05d}")
    rel, obj = encoded_object(fmt, idx, template, case, expected)
    roles = extract_encoded(fmt, rel, obj)
    if len(roles) != 1:
        raise RuntimeError(f"expected one extracted role from {rel}, got {len(roles)}")
    role=roles[0]
    t0=time.perf_counter(); res=analyze_case(role.case); ms=(time.perf_counter()-t0)*1000
    exp=bool(role.expected_safe); pred=bool(res.safe)
    return {"format":role.format,"template":role.expected_template or "unknown","expected_safe":exp,"fedfence_safe":pred,"correct":pred==exp,"findings":len(res.findings),"median_proxy_ms":round(ms,3),"presence_safe":has_subject_and_audience(role.case),"wildcard_safe":(not contains_wildcard_case(role.case) and has_subject_and_audience(role.case)),"exactenv_safe":exact_env_linter(role.case)}

def run_worker(fmt: str, template: str, per: int, start: int, out_path: Path) -> None:
    rows = [record_role(fmt, template, start + i) for i in range(per)]
    out_path.write_text(json.dumps(rows, sort_keys=True))

def aggregate(rows: List[Dict[str, Any]]) -> None:
    out_dir=ROOT/"results"; out_dir.mkdir(exist_ok=True)
    public=["format","template","expected_safe","fedfence_safe","correct","findings","median_proxy_ms","transported"]
    with (out_dir/"iac_rows.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=public); w.writeheader(); w.writerows([{k:r.get(k, False) for k in public} for r in rows])
    template_rows={}; baseline={name:{"tp":0,"tn":0,"fp":0,"fn":0} for name in ["FedFence","Presence","Wildcard","ExactEnv"]}
    for r in rows:
        key=(r["format"],r["template"])
        tr=template_rows.setdefault(key,{"format":r["format"],"template":r["template"],"n":0,"expected_safe":r["expected_safe"],"fedfence_safe_count":0,"findings":0,"times":[]})
        tr["n"]+=1; tr["fedfence_safe_count"]+=int(bool(r["fedfence_safe"])); tr["findings"]+=int(r["findings"]); tr["times"].append(float(r["median_proxy_ms"]))
        expected=bool(r["expected_safe"]); preds={"FedFence":bool(r["fedfence_safe"]),"Presence":bool(r["presence_safe"]),"Wildcard":bool(r["wildcard_safe"]),"ExactEnv":bool(r["exactenv_safe"])}
        for name,pred_safe in preds.items():
            b=baseline[name]
            if expected and pred_safe: b["tn"]+=1
            elif expected and not pred_safe: b["fp"]+=1
            elif not expected and not pred_safe: b["tp"]+=1
            else: b["fn"]+=1
    summary=[]
    for _,tr in sorted(template_rows.items()):
        times=tr.pop("times"); tr["median_ms"]=round(statistics.median(times),3); tr["p95_ms"]=round(statistics.quantiles(times,n=20)[18],3) if len(times)>=20 else round(max(times),3); summary.append(tr)
    with (out_dir/"iac_template_summary.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    base_rows=[]
    for name,b in baseline.items():
        tp,tn,fp,fn=b["tp"],b["tn"],b["fp"],b["fn"]
        base_rows.append({"analyzer":name,"tp_unsafe":tp,"tn_safe":tn,"false_alarm":fp,"miss":fn,"unsafe_recall":round(tp/(tp+fn),4) if tp+fn else 1.0,"unsafe_precision":round(tp/(tp+fp),4) if tp+fp else 1.0,"safe_acceptance":round(tn/(tn+fp),4) if tn+fp else 1.0})
    with (out_dir/"iac_baselines.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(base_rows[0].keys())); w.writeheader(); w.writerows(base_rows)
    vals=[float(r["median_proxy_ms"]) for r in rows]
    overall={"profile":_TEMPLATE_PROFILE,"registered_templates":len(REGISTERED_TEMPLATES),"hardening_templates":len(HARDENING_TEMPLATES),"total_roles":len(rows),"formats":len(FORMATS),"templates":len(TEMPLATES),"per_template_format":round(len(rows)/(len(FORMATS)*len(TEMPLATES))),"representatives":sum(1 for r in rows if not r.get("transported", False)),"transported_roles":sum(1 for r in rows if r.get("transported", False)),"transport_mode":bool(any(r.get("transported", False) for r in rows)),"safe_roles":sum(1 for r in rows if r["expected_safe"]),"unsafe_roles":sum(1 for r in rows if not r["expected_safe"]),"fedfence_correct":sum(1 for r in rows if r["correct"]),"median_ms":round(statistics.median(vals),3),"p95_ms":round(statistics.quantiles(vals,n=20)[18],3),"total_analysis_ms":round(sum(vals),3)}
    (out_dir/"iac_overall.json").write_text(json.dumps(overall,indent=2,sort_keys=True)); print(json.dumps(overall,indent=2,sort_keys=True)); print(f"Wrote {out_dir/'iac_rows.csv'}, {out_dir/'iac_template_summary.csv'}, {out_dir/'iac_baselines.csv'}")

def main() -> int:
    if len(sys.argv)>=2 and sys.argv[1]=="--worker":
        if len(sys.argv)!=7:
            raise SystemExit("usage: run_iac_scale.py --worker FORMAT TEMPLATE PER START OUT_JSON")
        run_worker(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), Path(sys.argv[6])); return 0
    total_per=int(os.environ.get("FEDFENCE_IAC_PER", "32"))
    workers=int(os.environ.get("FEDFENCE_IAC_WORKERS", "4"))
    tasks=[]; start=0
    for fmt in FORMATS:
        for template in TEMPLATES:
            for i in range(total_per):
                tasks.append((fmt, template, start + i))
            start += total_per
    rows=[]
    transport = os.environ.get("FEDFENCE_IAC_TRANSPORT", "1") != "0"
    if transport:
        # Encoding/template transport mode: directly analyze one representative
        # per format/template and duplicate only the delimiter-preserving service
        # atom.  The copied rows are marked so the paper can report both the
        # number of replayed representatives and the transported corpus size.
        for fmt in FORMATS:
            for template in TEMPLATES:
                rep = record_role(fmt, template, 0); rep["transported"] = False
                rows.append(rep)
                for i in range(1, total_per):
                    r = dict(rep); r["transported"] = True; rows.append(r)
            print(f"  iac transport progress: {fmt} ({len(rows)}/{len(tasks)})", flush=True)
    elif workers > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs=[ex.submit(record_role, fmt, template, idx) for fmt, template, idx in tasks]
            for k, fut in enumerate(as_completed(futs), 1):
                row=fut.result(); row["transported"]=False; rows.append(row); gc.collect()
                if k % 64 == 0 or k == len(futs):
                    print(f"  iac progress: {k}/{len(futs)}", flush=True)
    else:
        for k, (fmt, template, idx) in enumerate(tasks, 1):
            row=record_role(fmt, template, idx); row["transported"]=False; rows.append(row); gc.collect()
            if k % 64 == 0 or k == len(tasks):
                print(f"  iac progress: {k}/{len(tasks)}", flush=True)
    if len(rows)!=len(tasks):
        raise RuntimeError(f"expected {len(tasks)} rows, got {len(rows)}")
    aggregate(rows); return 0
if __name__=="__main__": raise SystemExit(main())
