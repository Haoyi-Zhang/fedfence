# Owned local release-bundle demonstration

This runnable program publishes a sorted catalog JSON and an HTML page from two
benign product records. Primary (`main`) and maintenance (`release`) jobs each
need three explicit operations: read `input/catalog.json`, write
`dist/catalog.json`, and write `dist/index.html`. `workflow.json` supplies six
required permission tuples after expansion over the two identities. The two
optional reads of the published JSON are permitted but not required. The
required set is neither empty nor inferred from the policy being reviewed.

From the artifact root, using Python 3.12 or later for the retained repair
generator's syntax, run with a **new** candidate-local output directory:

```sh
python -B scripts/run_owned_release_demo.py --out owned_demo/results/new-run
python -B owned_demo/test_release_bundle.py -v
```

The driver processes the complete self-constructed `source.tf.json` with the
existing `fedfence.iac.extract_file`, checks its intent against the separate
workflow contract, and calls the actual `fedfence.repair.synthesize_repair`.
It serializes and re-extracts the generated case, reviews strict packets with
two nonempty positive identity obligations, checks seven full receipt replays,
and executes the actual publisher in fourteen owned subprocess workspaces.
An additional owned unresolved-variable input is extracted syntactically but
rejected before synthesis. The two source-frontier controls and generated-case
roundtrip are separate from the frozen 24 public excerpts; they do not establish
Terraform evaluation, arbitrary source extraction, or external deployments.

`generated_policy.json` contains two deliberately separate fields. `trust` is
the existing generator's output. `permissions` is the explicit local operation
contract expanded over the reviewed identities, not an AWS permission policy
produced by FedFence. `release_bundle.py` checks identity admission and the exact
local grant before each of its three fixed operations. These are cooperative
application checks, not operating-system isolation against hostile programs.
Strict receipts cover the supplied trust-review packet, not a proof of the
publisher's implementation or permission enforcement. The publisher is not
transactional: if a later write is denied, an earlier authorized write may
remain in its owned workspace.

The same-information upper-only check intentionally omits the supplied lower
obligation. The direct two-sided lattice baseline independently expands finite
equality-bounded trust statements (including Deny) and checks both trust and
effective local permission bounds. No commercial product is used as a baseline.
The local checker and baseline use the same source/contract/permission inputs;
their agreement does not demonstrate a new solver capability or independence
of their shared assumptions.

The retained Windows CPython 3.12.14 manual run is
`results/windows-cpython31214/summary.json`. It records seven variants, fourteen
program invocations, ten content-verified completions, and four expected blocks.
The three availability-breaking variants pass upper-only containment; the
direct two-sided baseline agrees with the combined local judgment on all seven.
The generated policy and optional-read removal complete both jobs. Removing a
required write still passes trust-only review but blocks the primary publisher.
Broad trust or an unrelated grant can permit successful program completion while
violating the upper bound. The unrelated grant is classified but never exercised;
no private-data file is created or accessed.

Eight separate test methods include deletion of each of the six required grants
and malformed-data/job-scope controls. These are not added to the historical
204 tests, scientific stages, public corpus counts, or native CI evidence. This
demo has no automatic CI job, operational token, secret, network call, cloud
action, deployment authorization, or external write. Historical fixture time in
strict review is for deterministic replay, not current operational approval.
