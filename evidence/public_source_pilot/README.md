> **Superseded note:** This one-module boundary pilot is retained for provenance. The final package uses the frozen 17-candidate screening manifest and nine source-traceable changes under `evidence/public_changes/`.

# A public-source boundary observation, not a deployment corpus

Source repository: terraform-aws-modules/terraform-aws-iam
Commit: 55514b7873c411040395e024a422684998da77c2 (release commit identified by the repository API as v6.8.2)
File: modules/iam-role/main.tf
Source URL: https://github.com/terraform-aws-modules/terraform-aws-iam/blob/55514b7873c411040395e024a422684998da77c2/modules/iam-role/main.tf
Retrieved through the connected public GitHub read API on 2026-09-23.
License: Apache-2.0, confirmed from LICENSE at the same commit; license copy included.

The included file is a **verbatim excerpt**, beginning at `# GitHub OIDC` and ending after the audience condition. It is NOT the complete Terraform module and is NOT runnable Terraform. The SHA-256 in manifest.json hashes these excerpt bytes, not the remote full file. No transformation into a pretend concrete production role was performed.

The actual module contains dynamic statements, variable interpolation, `sts:TagSession` alongside `sts:AssumeRoleWithWebIdentity`, and `ForAllValues:StringEquals` on issuer/audience. These are concrete reasons that an exact-action, two-scalar-claim parser cannot be assumed to cover real modules. This is not evidence that the module is insecure. Resolving its effective policy requires caller inputs/Terraform evaluation; no caller intent or organization governance was obtained.

Sampling: one purposively selected public reusable module, chosen as a known OIDC implementation. No random sampling and no prevalence estimate. Oracle label: unknown. Owner confirmation: not requested. Cloud deployment: not observed. Direct download of a byte-complete snapshot from the execution container was blocked by DNS/network access; this excerpt was preserved from the connector's returned source text. This limitation is specific to the superseded pilot; the final claims rely on the separately frozen screening, change, maintenance, and source-frontier manifests and do not count this excerpt as a deployment row.
