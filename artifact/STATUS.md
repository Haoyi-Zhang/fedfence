# Artifact Status

The current artifact implements the supported AWS/GitHub Actions OIDC trust-admission fragment described in the paper.

Implemented and tested:

- exact GitHub federated-principal recognition;
- rejection of wildcard, mixed, malformed, and non-GitHub principals from positive safety proofs;
- provider-qualified condition-key normalization;
- provider-qualified keys for positive claim restrictions, with unsupported Allow conditions erased only as monotone restrictions and recorded in certificates;
- typed GitHub subject grammar for branch, tag, pull request, and environment subjects;
- issuer-audience intersection checking;
- repository-scoped environment governance facts and exported-governance premise checks;
- effective Allow-minus-supported-Deny policy semantics;
- replayable subject/audience witnesses;
- replayable effective case-level certificates verified by an independent replay path that does not call the high-level analyzer; the certificate runner separately checks analyzer agreement, supported Deny, and boundary facts;
- a standalone finite-domain label audit over registered and public rows that does not import the analyzer, certificate verifier, or FedFence package;
- a seven-family baseline suite over registered and public rows, separated from the high-level analyzer;
- an exported-governance audit over six settings fixtures and ten premises;
- a deployment-manifest runner for reviewer-supplied role-review packets;
- deterministic IaC extraction for direct trust JSON, Terraform JSON, and CloudFormation JSON;
- finite event-space selected-claim projection evaluation for repository identifiers, refs, environments, workflow references, and custom-property observations, including transport through direct JSON, Terraform JSON, and CloudFormation JSON metadata.

Scope of the artifact:

FedFence verifies the web-identity trust-admission boundary described in the paper: provider-qualified GitHub OIDC claims, exact federated principals, scalar string conditions, selected finite-event claims, supported Deny subtraction, declared release intent, and repository-scoped governance. It consumes review packets, deployment manifests, and settings exports, so it does not require live accounts or network access to replay the submitted proof evidence.

## Acceptance-profile additions

The current package contains an exhaustive finite projection-law checker, an adversarial policy matrix, a standalone finite-domain label audit, a stronger baseline suite, exported-governance checks, deployment-manifest rows, separated optional boundary-hardening rows, a reviewer-facing trusted-base report, and a title/abstract/evidence ledger in addition to the registered curated cases, public evidence, certificates, semantic grid, and IaC mutation corpus. These checks are included in `reproduce_all.sh` and recorded under `artifact/results/`.
