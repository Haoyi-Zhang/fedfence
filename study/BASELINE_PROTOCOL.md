# Real tools — execution status, not a capability cartoon

The execution environment has no `checkov`, `tfsec`, `trivy`, `opa` or `aws` executable. The initial DNS probe to the Python package registry failed. Therefore **zero vendor comparative runs are completed** in this iteration. `fse/results/external_tool_availability.json` records this status. A missing executable is not a negative security result.

`python scripts/run_external_tool.py --input INPUT --output OUTPUT -- COMMAND...` preserves the exact command, input hash, elapsed time, return code, stdout and stderr. It never assigns precision/recall automatically. Inspect commands before running: AWS/SaaS tools can transmit policy content and require authorization.

Run local product checks on the same extracted IaC/policy snapshot, with pinned executable version and rule identifiers. Save skips/timeouts as separate statuses. Preserve providers' native query semantics. For OPA, distinguish the OPA engine from a custom author-written Rego rule. For Access Analyzer, distinguish ValidatePolicy syntax/best-practice checks from reasoning-based custom checks. It is incorrect to equate absence of a lint warning with a proof of an independently written deployment intent.

First complete exact command validation against the chosen tool versions. Then freeze adapter mappings from tool findings to paper questions before inspecting results. Include a faithful existing-rule baseline, a custom-intent baseline, and a FedFence ablation where appropriate. Do not rename hand-written Python heuristics as product runs.
