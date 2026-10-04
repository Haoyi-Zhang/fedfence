# Packet schema and full-review receipt

`schemas/review-packet.schema.json` describes the packet's JSON shape. It is not the whole release-review specification. The executable validator in `fse_workflow/contract.py` additionally checks matching repository/role scope, literal identity values, approval/body digests, distinct declared author/reviewer identifiers, timestamp parsing and freshness, and other cross-field constraints. The supported fragment and positive checks are separate executable gates. Passing a generic JSON Schema validator alone is never a FedFence `pass`.

`schemas/two-sided-receipt.schema.json` documents the receipt envelope. It does not make the envelope authenticated, and JSON Schema cannot establish that its digest matches its contents. `fse_workflow/receipt.py` checks the exact envelope fields, schema tag, false source-authentication assertion and envelope digest, then reruns the current gate. It compares the full selected semantic result rather than trusting a stored verdict. A changed implementation or stale snapshot causes a replay disagreement or an unknown gate result rather than a reusable old pass.

For a result with invalid early premises, some semantic fields are null. This is deliberate: missing safety/certificate evidence is not synthesized. `receipt_replay_ok` means the recorded semantic result agrees with current reevaluation. It does not turn a faithfully replayed failure or unknown into a pass.

Full review replay and the inherited backend certificate replay have different objects. The backend certificate concerns the core safety analysis. The full receipt additionally binds the separate contract, required identities, wrapper fragment decision and input/implementation dependencies. Neither is a signed attestation or an independent verification implementation.

## Additional executable boundaries

The strict fragment separately requires an explicit supported policy version and string-typed optional policy IDs. A scalar empty condition string is equivalent to a singleton list containing that string; an empty alternative list remains invalid. These policy constraints are not implied by the packet envelope schema alone.

Only `now=None` chooses the current UTC clock. Explicit false-like values such as an empty string or Boolean are malformed inputs. For four snapshot times `s_i` and maximum age `tau`, the accepted caller-time interval is `[max(s_i), min(s_i+tau)]`, inclusive when nonempty. Expiration is checked again at replay.

The positive matcher reports named budget exhaustion, which propagates as `unknown`; it is not treated as evidence that a required identity is missing. Regular-language issuer refinements narrow the typed subject constructor and audience language. The distinct finite study adapter does not change strict-profile eligibility.

## Character-domain migration

The current atomic certificate format is version 3 and the effective-case format is version 6, with `character_domain: python-str-codepoints-v1`. Legacy formats lack the corrected character-domain obligation and are rejected for regeneration, not silently accepted. A producer cannot remove a literal singleton, constructor boundary, or the nonempty OTHER class from an atomic certificate's alphabet. The verifier checks support coverage before checking transitions; the residual obligation uses the domain cardinality, not the selector used by the producer.

The complete receipt schema remains v1 because its envelope is unchanged. Its implementation hash and embedded certificate hash change, so old full receipts do not replay as current positive evidence. Re-run the original packet at the caller's actual check time; a stale packet remains unknown. Recomputing an envelope digest or changing a version field does not regenerate a correct certificate.
