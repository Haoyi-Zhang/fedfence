# Character support correction — 2026-10-04

## Defect and affected boundary

The previous `regular.alphabet_from_patterns` chose a nonliteral representative from a fixed preferred pool. When that pool was fully literal, its fallback added the same pool rather than a member of the still-nonempty remainder of the actual string domain. Universal containment could then search a strict subdomain. The effective replayer used the same construction, so agreement did not rule out this omission. `tosem/history/character_domain_previous_observation.json` records a direct local observation of the previous source from the uploaded archive, with archive/source hashes: 75 literal singleton characters, 75 support characters, no OTHER representative.

The atomic invariant verifier had a related boundary: it read the alphabet supplied by the certificate without first requiring complete support. Closing an invariant under an incomplete set of transitions does not prove closure under the intended domain.

## Domain, partition and exactness

The model is explicitly `python-str-codepoints-v1`: U+0000 through U+10FFFF, including code points representable in Python strings even when they are not valid standalone UTF-8 text. The scalar matcher performs exact code-point matching; no Unicode normalization, grapheme segmentation or byte matching is implied. The strict packet serializer retains its UTF-8 requirement. A direct-library surrogate test is not a provider-token claim or authorization to admit such a value into a packet.

Let S contain all actual equality literals, all non-metacharacter glob literals, every fixed constructor literal and every member of the constructor exclusion sets. The current constructor predicates exclude `/:*?` in owner/repository components and `:*?` in branch/tag/environment suffixes. For nonempty Gamma minus S, choose one r in that remainder and use A = S union {r}; only when S is the entire domain may the residual class be absent. The preferred pool changes the representative's presentation, not the domain.

Projection fixes S pointwise and maps every remaining character to r. Each singleton test, finite exclusion and unrestricted consuming transition has the same result before and after projection. Epsilon transitions do not consume input. Induction over automaton runs proves language-membership preservation; Boolean combinations and the two-coordinate effective Allow-minus-Deny relation preserve it as well. Hence a concrete violation has a representative violation, and a representative violation is a concrete value in the declared abstract domain. The manuscript gives the proof and its predicate assumptions. New character predicates, ranges, encodings or normalization rules require a new partition argument.

Raw NFA construction remains deliberately finite-alphabet. `glob('*', A).accepts(x)` does not implicitly project an out-of-support concrete word. Use the scalar checker, or construct complete support and explicitly project. This distinction prevents a search alphabet from being mistaken for the concrete character domain.

## Changes in the existing implementation

`regular.py` now traverses actual string containers (including tuples/generators) rather than their Python representations, preserves typed equality metacharacters, treats `base` as representative preferences, searches the full domain after pool exhaustion and validates complete support with a cardinality-based residual check. No second regex engine or replacement automata implementation is introduced.

`github.py` supplies the literal/exclusion boundaries needed by the partition. Its scalar parser now uses the same star/question-mark exclusions and whole-component matching as the existing typed NFA and positive checker. These exclusions are the implemented abstract grammar, not a newly claimed complete provider naming rule.

`analyzer.py` and effective certificate recomputation both add constructor boundaries and explicitly validate support before starting search. An insufficient support raises an error; the existing strict backend error boundary returns `unknown` rather than a positive verdict.

`certificate.py` validates atomic alphabet coverage before witness/invariant checks, binds the domain and rejects unknown/legacy domain versions. Atomic certificates are version 3; effective-case certificates are version 6. Full receipts bind the changed implementation and certificate digests. Old certificates/receipts must be regenerated, not relabeled. The supported pass/fail/unknown decision rule and invalid-first precedence are unchanged.

`conformance.py` documents the same full code-point domain while retaining its separately implemented scalar matcher. Its domain is not narrowed to make it agree with a deficient search support. The component witness script also uses constructor-aware support.

## Executed evidence and limits

The current ordinary suite has 194 methods: the prior 146 and 48 new checks. New checks cover saturation of the full preferred pool, all ASCII values and the whole basic multilingual plane; an additional listed representative; equality `*`/`?`; container traversal and plain pattern tuples whose first value spells an operator; constructor positions; missing/duplicate certificate symbols; wrong/legacy domains; actual review controls; receipt invalidation; and stale/invalid inputs.

`make character-domain` runs a separate audit. Its three full-code-point sweeps yield 3,342,336 **primitive signature comparisons**, not that many policies or deployments. The concrete/quotient matcher comparison contains 57,498 equality/glob pairs over declared bounds, without adding the concrete word to the search support. Sixty further checks insert twelve characters at five typed-constructor positions. Four regular-language cases include closed positive controls, and three strict packets exercise fail, pass and stale unknown with full receipt replay.

Two local rejection challenges have passing controls: suppressing the residual selector must be caught by coverage; bypassing certificate coverage must defeat the incomplete-support rejection test. These are selected sensitivity checks, not a mutation-adequacy score. The production coverage checker and the new recursive/scalar test oracles do not call the fresh-character selector when deciding their expected coverage or membership results. Parser/NFA/runtime assumptions remain shared, so this is not an independent whole-system proof.

All inputs are local synthetic strings or the previously supplied static project materials. No actual cloud account, credential, public workflow, live token request, third-party exploitation, or user/product benchmark is involved. Current detailed results are in `tosem/results/character_domain_audit.json`; all ten evidence steps are part of `make reproduce`.

## Plain pattern sequences and tagged groups

The four atomic certificate builders normalize their plain glob sequence parameters to lists before collecting predicates. Otherwise a valid two-element pattern tuple beginning with `like`, `equals`, `literal` or `glob` could be mistaken for a tagged group by the generic support collector. Tagged policy groups remain explicit and operator-aware. All four builders check support coverage before claiming either safe or unsafe. The new tests compare list/tuple forms and inject a missing-representative failure to verify each generator refuses an incomplete support.
