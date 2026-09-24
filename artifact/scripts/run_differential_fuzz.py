#!/usr/bin/env python3
from __future__ import annotations
import csv, itertools, json, random, statistics, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.regular import alphabet_from_patterns, contains_witness, glob, intersection_language_difference_witness, union_globs  # noqa: E402

ALPH = tuple("ab:$")
LITS = list(ALPH) + ["*", "?"]
MAX_LEN = 5
SEED = 20270603

def words():
    yield ""
    for n in range(1, MAX_LEN + 1):
        for tup in itertools.product(ALPH, repeat=n):
            yield "".join(tup)
WORDS = list(words())

def brute(pattern: str, word: str) -> bool:
    dp = [[False] * (len(word) + 1) for _ in range(len(pattern) + 1)]
    dp[0][0] = True
    for i, ch in enumerate(pattern, 1):
        if ch == "*":
            dp[i][0] = dp[i-1][0]
            for j in range(1, len(word)+1):
                dp[i][j] = dp[i-1][j] or dp[i][j-1]
        elif ch == "?":
            for j in range(1, len(word)+1):
                dp[i][j] = dp[i-1][j-1]
        else:
            for j in range(1, len(word)+1):
                dp[i][j] = dp[i-1][j-1] and word[j-1] == ch
    return dp[len(pattern)][len(word)]

def gen_pattern(rng: random.Random) -> str:
    n = rng.randint(0, 5)
    p = "".join(rng.choice(LITS) for _ in range(n))
    # Avoid only-star cases dominating the corpus.
    if p in {"*", "**", "***"}:
        p = rng.choice(["a*", "*:b", "?$", "a?b"])
    return p

def main() -> int:
    rng = random.Random(SEED)
    pair_checks = int(sys.argv[1]) if len(sys.argv) > 1 else int(__import__("os").environ.get("FEDFENCE_FUZZ_PAIRS", "1200"))
    triple_checks = int(sys.argv[2]) if len(sys.argv) > 2 else int(__import__("os").environ.get("FEDFENCE_FUZZ_TRIPLES", "800"))
    rows = []
    t0 = time.perf_counter()
    ok = 0
    for k in range(pair_checks):
        a, b = gen_pattern(rng), gen_pattern(rng)
        alph = alphabet_from_patterns([a], [b], base=ALPH)
        wa = contains_witness(glob(a, alph), glob(b, alph), alph)
        brute_w = next((w for w in WORDS if brute(a, w) and not brute(b, w)), None)
        valid = True
        if brute_w is not None:
            valid = wa is not None and brute(a, wa) and not brute(b, wa)
        elif wa is not None and len(wa) <= MAX_LEN:
            valid = brute(a, wa) and not brute(b, wa)
        ok += int(valid)
        rows.append({"kind":"pair", "a":a, "b":b, "i":"", "valid":valid, "witness":wa or "", "brute_bounded":brute_w or ""})
        if not valid:
            break
    for k in range(triple_checks):
        a, b, i = gen_pattern(rng), gen_pattern(rng), gen_pattern(rng)
        alph = alphabet_from_patterns([a], [b], [i], base=ALPH)
        wa = intersection_language_difference_witness(glob(a, alph), glob(b, alph), glob(i, alph), alph)
        brute_w = next((w for w in WORDS if brute(a, w) and brute(b, w) and not brute(i, w)), None)
        valid = True
        if brute_w is not None:
            valid = wa is not None and brute(a, wa) and brute(b, wa) and not brute(i, wa)
        elif wa is not None and len(wa) <= MAX_LEN:
            valid = brute(a, wa) and brute(b, wa) and not brute(i, wa)
        ok += int(valid)
        rows.append({"kind":"triple", "a":a, "b":b, "i":i, "valid":valid, "witness":wa or "", "brute_bounded":brute_w or ""})
        if not valid:
            break
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with (out / "differential_fuzz.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    elapsed = (time.perf_counter() - t0) * 1000
    overall = {"seed": SEED, "checks": len(rows), "pair_checks": pair_checks, "triple_checks": triple_checks, "correct": sum(1 for r in rows if r["valid"]), "alphabet": "".join(ALPH), "bounded_words": len(WORDS), "max_word_length": MAX_LEN, "elapsed_ms": round(elapsed, 3)}
    (out / "differential_fuzz_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True))
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if overall["correct"] == overall["checks"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
