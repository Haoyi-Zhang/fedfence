# FSE semantic revision — specification versus executable policy

This is a proposed replacement for the S&P exposition, not a claim that the submitted S&P PDF already made these distinctions. The implemented finite checker is `fse_workflow/semantics.py`. It is not a proof assistant.

## 1. Restrict the state domain first

Let Ω contain possible workflow states, let M ⊆ Ω contain states the reviewed issuer/governance model considers mintable, and let Φ ⊆ Ω be the independently reviewed intent. Define R = M ∩ Φ and restrict π to M. All images/inverse images below use this restricted domain. An unmintable intended state must not make an identical observation from a mintable unintended state appear safe.

Let Y = π(M), B = π(M \ R), and H = Y \ B. H contains observations whose **entire mintable fiber** is intended (must-safe observations). The existential image π(R) may contain ambiguous observations and is insufficient by itself.

For a supported effective policy E, admitted states are Adm(E) = {ω ∈ M | π(ω) ∈ E}.

**State-safety equivalence.** Adm(E) ⊆ R iff Y ∩ E ⊆ H.

Proof: if an admitted observation belongs to B, it has a mintable unintended preimage, contradicting state safety. Conversely, if an admitted state is unintended, its observation belongs to B and not H. This equivalence does not require saturation. It requires a correct and complete supplied M for the desired deployment claim.

**Saturated special case.** R is saturated on M iff π(R) ∩ π(M \ R) is empty. In that case H = π(R), recovering the familiar claim containment test. If saturation fails, no predicate over these claims can accept every intended state and reject every unintended state. A more restrictive policy can still be safe by rejecting mixed observation classes. Do not confuse non-definability of the full intent with impossibility of every safe policy.

## 2. Two-sided conformance for configuration maintenance

Universal safety is an upper-bound property: `Y ∩ E ⊆ H` excludes every
issuer-mintable observation whose fiber contains an unintended state.  A policy
edit can satisfy that property by deleting all authority, so it is insufficient
for change maintenance when known deployment paths must remain available.

A reviewed contract may therefore record a finite set `R_req ⊆ H` of required
token observations.  Two-sided conformance is:

`Y ∩ E ⊆ H` and `R_req ⊆ Y ∩ E ∩ H`.

The first conjunct is universal over the modeled issuer/policy language.  The
second is deliberately finite and existential: every listed regression example
must still be issuer-mintable, intended, and effectively admitted.  If a listed
token lies outside the issuer or intent model, the result is `unknown`, because
the contract and model disagree.  If it is mintable and intended but no longer
admitted, the result is `fail` with a required-identity-loss witness.

`R_req` is not claimed to equal the complete lower-bound language.  It is the
configuration analogue of a regression-test suite: useful for preserving known
paths, but incomplete unless the organization supplies a complete availability
specification.

## 3. Effective Deny from the start

For supported statements let A be the union of Allow token relations and D the union of Deny token relations. E = A \ D. Every containment test and witness replay uses E. For each Allow relation A_i, check A_i \ D against the same intent. This is equivalent to checking (⋃ A_i) \ D, but checking un-subtracted A_i is only sufficient, not necessary, for effective safety.

Subtract Deny at the tuple/relation level, not independently per coordinate. With A={main,dev}×{sts,other} and D={(dev,sts),(main,other)}, both (main,sts) and (dev,other) survive. Subtracting coordinate projections incorrectly removes all authority. This example is an executable regression.

Structural support and governance premises are separate preconditions. Bad-language emptiness cannot prove principal support, extraction fidelity, source authenticity, or governance freshness by itself.

## 4. Observation-basis nomenclature

An inclusion-minimal basis has no strictly smaller defining subset. A minimum-cardinality basis has the least size of all defining subsets. The former may contain solutions of different sizes. A single perfect discriminator a and a pair {b,c} may both be inclusion-minimal while only {a} is minimum-cardinality.

The frozen `minimal_claim_bases` enumerator stops at the first successful cardinality. The new API returns both collections separately and includes the empty set for constant predicates. Exponential enumeration is explicitly bounded to 16 candidate coordinates. Missing state coverage is not inferred by this routine.

## 5. Maximal narrowing

For claim intent I and issuer image G within token universe U, the greatest safe sublanguage of P is P ∩ (I ∪ (U \ G)). U is a universe of token tuples/strings, not merely the finite character alphabet. A finite character alphabet can still generate infinitely many words. The finite five-element audit is a sanity check, not the proof of the unbounded-language statement.

This is a greatest **language**, not necessarily a policy expressible by the supported IAM syntax or a repair preserving all desired executions. The change-review prototype does not claim to synthesize a globally optimal deployable IAM repair.

## 6. Current proof-to-code boundary

The new finite semantics module checks the equivalence and basis definitions on explicitly supplied states. The deployment gate uses a strict sub/aud backend with normalized governance assumptions. They are separate implementations with different domains, not a single mechanized refinement chain. The original parser/NFA/issuer TCB remains. Certificate replay is independent of the high-level analyzer but shares lower-level code.

The 65,536 four-state/two-observation checks and regression tests are local implementation evidence. They do not establish correspondence to live GitHub/AWS behavior or completeness of M.
