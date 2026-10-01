from .normalized_study import decide, certificate, replay
AUD="sts.amazonaws.com"
VALID="repo:acme/api:ref:refs/heads/main"
EXTRA=VALID+":extra"
def tok(s): return {"sub":s,"aud":AUD}
def exact(s): return {"sub":s,"aud":AUD}

def run():
    # Explicit issuer domains may contain a token outside the legacy constructor grammar.
    p={"explicit_issuer":[tok(EXTRA)],"allow":[exact(EXTRA)],"intent":[exact(EXTRA)],"required":[tok(EXTRA)]}
    r=decide(**p)
    assert (r.status,r.exit_code)==("pass",0),r
    assert replay(certificate(p,r)).status=="pass"
    # The same positive obligation outside the explicit issuer relation is inconsistent, not vacuous pass.
    p2={**p,"explicit_issuer":[tok(VALID)]}
    r2=decide(**p2)
    assert (r2.status,r2.exit_code)==("unknown",2),r2
    assert any(f.code=="required-token-outside-issuer-domain" for f in r2.findings)
    # Legal legacy branch control.
    p3={"explicit_issuer":[tok(VALID)],"allow":[exact(VALID)],"intent":[exact(VALID)],"required":[tok(VALID)]}
    assert decide(**p3).status=="pass"
    # Tri-state precedence: invalid dominates latent fail findings without erasing them.
    cases=[
      ({"explicit_issuer":[tok(VALID),tok(EXTRA)],"allow":[{"sub":"repo:acme/api:*","aud":AUD}],"intent":[exact(VALID)],"required":[],"invalid":["bad-contract"]},"unknown","admission-expansion"),
      ({"explicit_issuer":[tok(VALID)],"allow":[],"intent":[exact(VALID)],"required":[tok(VALID)],"invalid":["bad-contract"]},"unknown","required-token-not-admitted"),
      ({"explicit_issuer":[tok(VALID)],"allow":[exact(VALID)],"intent":[exact(VALID)],"required":[],"invalid":["bad-contract"]},"unknown",None),
      ({"explicit_issuer":[tok(VALID)],"allow":[],"intent":[exact(VALID)],"required":[tok(VALID)],"invalid":[]},"fail","required-token-not-admitted"),
    ]
    for args,status,latent in cases:
        x=decide(**args); assert x.status==status,(args,x)
        codes={f.code for f in x.findings+x.latent_findings}
        if latent: assert latent in codes,(latent,codes)
    return {"status":"pass","checks":7}
if __name__=="__main__":
    import json; print(json.dumps(run(),sort_keys=True))
