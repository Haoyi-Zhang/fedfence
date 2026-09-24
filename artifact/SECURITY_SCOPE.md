# Security Scope

FedFence proves a narrow admission property: every token that the modeled CI issuer can mint and the modeled trust policy can admit must satisfy a declared release intent, subject to visible governance premises.

In scope:

- GitHub Actions default OIDC subject forms;
- AWS-style web-identity trust policies over provider-qualified subject and audience claims;
- equality and glob-like positive conditions in supported operators;
- supported Deny statements as monotone policy narrowing;
- exact federated-principal checks;
- environment-governance facts scoped by owner, repository, and environment;
- exported branch, tag, environment, and reusable-workflow settings used as premise evidence;
- direct trust JSON, Terraform JSON, and CloudFormation JSON containers.

Outside scope:

- downstream IAM permissions, resource policies, session tags, and role chaining;
- cloud-provider semantics not represented by subject/audience trust conditions;
- prevalence measurement over organizations not supplied as review packets;
- exploitability of a particular workflow after a trust-policy counterexample is found; this composes with workflow analyzers.

Unsupported syntax is not silently approximated into a safe proof. It is reported as outside-core so that the positive theorem remains falsifiable.
